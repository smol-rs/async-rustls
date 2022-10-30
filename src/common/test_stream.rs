use super::Stream;
use futures_util::future::poll_fn;
use futures_util::task::noop_waker_ref;
use rustls::{ClientConnection, Connection, ServerConnection};
use smol::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io::{self, Cursor, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

struct Good<'a>(&'a mut Connection);

impl<'a> AsyncRead for Good<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        mut buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.0.write_tls(buf.by_ref()))
    }
}

impl<'a> AsyncWrite for Good<'a> {
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

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.send_close_notify();
        self.poll_flush(cx)
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

struct Expected(Cursor<Vec<u8>>);

impl AsyncRead for Expected {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        Poll::Ready(std::io::Read::read(&mut this.0, buf))
    }
}

impl AsyncWrite for Expected {
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
        const FILE: &[u8] = include_bytes!("../../README.md");

        let (server, mut client) = make_pair();
        let mut server = Connection::from(server);
        poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

        io::copy(&mut Cursor::new(FILE), &mut server.writer())?;
        server.send_close_notify();

        {
            let mut good = Good(&mut server);
            let mut stream = Stream::new(&mut good, &mut client);

            let mut buf = Vec::new();
            dbg!(stream.read_to_end(&mut buf).await)?;
            assert_eq!(buf, FILE);

            dbg!(stream.write_all(b"Hello World!").await)?;
            stream.session.send_close_notify();

            dbg!(stream.close().await)?;
        }

        let mut buf = String::new();
        dbg!(server.process_new_packets()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        dbg!(server.reader().read_to_string(&mut buf))?;
        assert_eq!(buf, "Hello World!");

        Ok(()) as io::Result<()>
    })
}

#[test]
fn stream_bad() -> io::Result<()> {
    smol::block_on(async {
        let (server, mut client) = make_pair();
        let mut server = Connection::from(server);
        poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;
        client.set_buffer_limit(Some(1024));

        let mut bad = Pending;
        let mut stream = Stream::new(&mut bad, &mut client);
        assert_eq!(
            poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x42; 8])).await?,
            8
        );
        assert_eq!(
            poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x42; 8])).await?,
            8
        );
        let r = poll_fn(|cx| stream.as_mut_pin().poll_write(cx, &[0x00; 1024])).await?; // fill buffer
        assert!(r < 1024);

        let mut cx = Context::from_waker(noop_waker_ref());
        let ret = stream.as_mut_pin().poll_write(&mut cx, &[0x01]);
        assert!(ret.is_pending());

        Ok(()) as io::Result<()>
    })
}

#[test]
fn stream_handshake() -> io::Result<()> {
    smol::block_on(async {
        let (server, mut client) = make_pair();
        let mut server = Connection::from(server);

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
fn stream_handshake_eof() -> io::Result<()> {
    smol::block_on(async {
        let (_, mut client) = make_pair();

        let mut bad = Expected(Cursor::new(Vec::new()));
        let mut stream = Stream::new(&mut bad, &mut client);

        let mut cx = Context::from_waker(noop_waker_ref());
        let r = stream.handshake(&mut cx);
        assert_eq!(
            r.map_err(|err| err.kind()),
            Poll::Ready(Err(io::ErrorKind::UnexpectedEof))
        );

        Ok(()) as io::Result<()>
    })
}

// see https://github.com/tokio-rs/tls/issues/77
#[test]
fn stream_handshake_regression_issues_77() -> io::Result<()> {
    smol::block_on(async {
        let (_, mut client) = make_pair();

        let mut bad = Expected(Cursor::new(b"\x15\x03\x01\x00\x02\x02\x00".to_vec()));
        let mut stream = Stream::new(&mut bad, &mut client);

        let mut cx = Context::from_waker(noop_waker_ref());
        let r = stream.handshake(&mut cx);
        assert_eq!(
            r.map_err(|err| err.kind()),
            Poll::Ready(Err(io::ErrorKind::UnexpectedEof))
        );

        Ok(()) as io::Result<()>
    })
}

#[test]
fn stream_eof() -> io::Result<()> {
    smol::block_on(async {
        let (server, mut client) = make_pair();
        let mut server = Connection::from(server);
        poll_fn(|cx| do_handshake(&mut client, &mut server, cx)).await?;

        let mut bad = Expected(Cursor::new(Vec::new()));
        let mut stream = Stream::new(&mut bad, &mut client);

        let mut buf = Vec::new();
        let result = stream.read_to_end(&mut buf).await;
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::UnexpectedEof)
        );

        Ok(()) as io::Result<()>
    })
}

fn make_pair() -> (ServerConnection, ClientConnection) {
    use std::convert::TryFrom;

    let (sconfig, cconfig) = utils::make_configs();
    let server = ServerConnection::new(sconfig).unwrap();

    let domain = rustls::ServerName::try_from("foobar.com").unwrap();
    let client = ClientConnection::new(cconfig, domain).unwrap();

    (server, client)
}

fn do_handshake(
    client: &mut ClientConnection,
    server: &mut Connection,
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

// Share `utils` module with integration tests
include!("../../tests/utils.rs");
