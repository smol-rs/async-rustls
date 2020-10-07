use async_rustls::{client::TlsStream, TlsConnector};
use futures_lite::{future, future::Future, ready};
use rustls::ClientConfig;
use smol::net::TcpStream;
use smol::prelude::*;
use smol::Timer;
use std::io::{self, BufRead, BufReader, Cursor};
use std::net::SocketAddr;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

struct Read1<T>(T);

impl<T: AsyncRead + Unpin> Future for Read1<T> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut buf = [0];
        ready!(Pin::new(&mut self.0).poll_read(cx, &mut buf))?;
        Poll::Pending
    }
}

enum Either<A, B> {
    Left(A),
    Right(B),
}

async fn send(
    config: Arc<ClientConfig>,
    addr: SocketAddr,
    data: &[u8],
) -> io::Result<TlsStream<TcpStream>> {
    let connector = TlsConnector::from(config).early_data(true);
    let stream = TcpStream::connect(&addr).await?;
    let domain = webpki::DNSNameRef::try_from_ascii_str("testserver.com").unwrap();

    let mut stream = connector.connect(domain, stream).await?;
    stream.write_all(data).await?;
    stream.flush().await?;

    {
        let stream = &mut stream;

        // sleep 1s
        //
        // see https://www.mail-archive.com/openssl-users@openssl.org/msg84451.html
        let sleep1 = Timer::after(Duration::from_secs(1));
        match future::or(
            async move { Either::Left(Read1(stream).await) },
            async move { Either::Right(sleep1.await) },
        )
        .await
        {
            Either::Right(_) => {}
            Either::Left(Err(err)) => return Err(err),
            Either::Left(Ok(_)) => unreachable!(),
        }
    }

    stream.close().await?;
    Ok(stream)
}

struct DropKill(Child);

impl Drop for DropKill {
    fn drop(&mut self) {
        self.0.kill().unwrap();
    }
}

#[test]
fn test_0rtt() -> io::Result<()> {
    smol::block_on(async {
        let mut handle = Command::new("openssl")
            .arg("s_server")
            .arg("-early_data")
            .arg("-tls1_3")
            .args(&["-cert", "./tests/end.cert"])
            .args(&["-key", "./tests/end.rsa"])
            .args(&["-port", "12354"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map(DropKill)?;

        // wait openssl server
        Timer::after(Duration::from_secs(1)).await;

        let mut config = ClientConfig::new();
        let mut chain = BufReader::new(Cursor::new(include_str!("end.chain")));
        config.root_store.add_pem_file(&mut chain).unwrap();
        config.versions = vec![rustls::ProtocolVersion::TLSv1_3];
        config.enable_early_data = true;
        let config = Arc::new(config);
        let addr = SocketAddr::from(([127, 0, 0, 1], 12354));

        let io = send(config.clone(), addr, b"hello").await?;
        assert!(!io.get_ref().1.is_early_data_accepted());

        let io = send(config, addr, b"world!").await?;
        assert!(io.get_ref().1.is_early_data_accepted());

        let stdout = handle.0.stdout.as_mut().unwrap();
        let mut lines = BufReader::new(stdout).lines();

        let has_msg1 = lines.by_ref().any(|line| line.unwrap().contains("hello"));
        let has_msg2 = lines.by_ref().any(|line| line.unwrap().contains("world!"));

        assert!(has_msg1 && has_msg2);

        Ok(())
    })
}
