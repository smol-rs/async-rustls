use super::Stream;
use futures_lite::future::poll_fn;
use futures_lite::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures_lite::ready;
use rustls::server::NoClientAuth;
use rustls_pemfile::{certs, rsa_private_keys};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, Certificate, PrivateKey, RootCertStore, ServerName, ConnectionCommon};
use std::convert::TryFrom;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

struct Good<'a, IO>(&'a mut ConnectionCommon<IO>);

impl<'a, IO> AsyncRead for Good<'a, IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.0.write_tls(buf.by_ref()))
    }
}

impl<'a, IO> AsyncWrite for Good<'a, IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = self.0.read_tls(buf.by_ref())?;
        self.0
            .process_new_packets()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0
            .process_new_packets()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.send_close_notify();
        Poll::Ready(Ok(()))
    }
}

struct Pending;

impl AsyncRead for Pending {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }
}

impl AsyncWrite for Pending {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Eof;

impl AsyncRead for Eof {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }
}

impl AsyncWrite for Eof {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn stream_good() -> io::Result<()> {
    smol::block_on(async {
        const FILE: &[u8] = include_bytes!("../../Cargo.toml");

        let (mut server, mut client) = make_pair();
        poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;
        io::copy(&mut Cursor::new(FILE), &mut server.writer())?;

        {
            let mut good = Good(&mut server);
            let mut stream = Stream::new(&mut good, &mut client);

            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await?;
            assert_eq!(buf, FILE);
            stream.write_all(b"Hello World!").await?;
            stream.flush().await?;
        }

        let mut buf = String::new();
        server.reader().read_to_string(&mut buf)?;
        assert_eq!(buf, "Hello World!");

        Ok(()) as io::Result<()>
    })
}

#[test]
fn stream_handshake() -> io::Result<()> {
    smol::block_on(async {
        let (mut server, mut client) = make_pair();

        {
            let mut good = Good(&mut server);
            let mut stream = Stream::new(&mut good, &mut client);
            let (r, w) = poll_fn(|cx| stream.handshake(cx)).await?;

            assert!(r > 0);
            assert!(w > 0);

            poll_fn(|cx| stream.handshake(cx)).await?; // finish server handshake
        }

        assert!(!server.is_handshaking());
        assert!(!client.is_handshaking());

        Ok(()) as io::Result<()>
    })
}

#[test]
fn stream_eof() -> io::Result<()> {
    smol::block_on(async {
        let (mut server, mut client) = make_pair();
        poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

        let mut good = Good(&mut server);
        let mut stream = Stream::new(&mut good, &mut client).set_eof(true);

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        assert_eq!(buf.len(), 0);

        Ok(()) as io::Result<()>
    })
}

fn make_pair() -> (ServerConnection, ClientConnection) {
    const CERT: &str = include_str!("../../tests/end.cert");
    const CHAIN: &str = include_str!("../../tests/end.chain");
    const RSA: &str = include_str!("../../tests/end.rsa");

    let cert = certs(&mut BufReader::new(Cursor::new(CERT))).unwrap().into_iter().map(Certificate).collect();
    let mut keys = rsa_private_keys(&mut BufReader::new(Cursor::new(RSA))).unwrap();
    let sconfig = ServerConfig::builder().with_safe_defaults().with_client_cert_verifier(NoClientAuth::new())
        .with_single_cert(cert, PrivateKey(keys.pop().unwrap())).unwrap();
    let server = ServerConnection::new(Arc::new(sconfig)).unwrap();

    let domain = ServerName::try_from("localhost").unwrap();
    let mut chain = BufReader::new(Cursor::new(CHAIN));
    let mut store = RootCertStore::empty();

    for cert in rustls_pemfile::certs(&mut chain).into_iter().flatten() {
        store.add(&Certificate(cert)).unwrap();
    }

    let cconfig = ClientConfig::builder().with_safe_defaults()
        .with_root_certificates(store)
        .with_no_client_auth();
    let client = ClientConnection::new(Arc::new(cconfig), domain).unwrap();

    (server, client)
}

fn do_handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    let mut good = Good(server);
    let mut stream = Stream::new(&mut good, client);

    while stream.session.is_handshaking() {
        ready!(stream.handshake(cx))?;
    }

    while stream.session.wants_write() {
        ready!(stream.write_io(cx))?;
    }

    Poll::Ready(Ok(()))
}
