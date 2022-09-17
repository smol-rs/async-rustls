use async_rustls::{client::TlsStream, TlsConnector};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use smol::net::TcpStream;
use smol::prelude::*;
use std::convert::TryFrom;
use std::io;
use std::net::ToSocketAddrs;
use std::sync::Arc;

async fn get(
    config: Arc<ClientConfig>,
    domain: &str,
    port: u16,
) -> io::Result<(TlsStream<TcpStream>, String)> {
    let connector = TlsConnector::from(config);
    let input = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain);

    let addr = (domain, port).to_socket_addrs()?.next().unwrap();
    let domain = ServerName::try_from(domain).unwrap();
    let mut buf = Vec::new();

    let stream = TcpStream::connect(&addr).await?;
    let mut stream = connector.connect(domain, stream).await?;
    stream.write_all(input.as_bytes()).await?;
    stream.flush().await?;
    stream.read_to_end(&mut buf).await?;

    Ok((stream, String::from_utf8(buf).unwrap()))
}

#[test]
fn test_tls12() -> io::Result<()> {
    smol::block_on(async {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(all_roots());
        let config = ClientConfig::builder()
            .with_cipher_suites(rustls::DEFAULT_CIPHER_SUITES)
            .with_kx_groups(&rustls::ALL_KX_GROUPS)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let config = Arc::new(config);
        let domain = "tls-v1-2.badssl.com";

        let (_, output) = get(config.clone(), domain, 1012).await?;
        assert!(output.contains("<title>tls-v1-2.badssl.com</title>"));

        Ok(())
    })
}

#[ignore]
#[should_panic]
#[test]
fn test_tls13() {
    unimplemented!("todo https://github.com/chromium/badssl.com/pull/373");
}

#[test]
fn test_modern() -> io::Result<()> {
    smol::block_on(async {
        let mut roots = RootCertStore::empty();
        roots.add_server_trust_anchors(all_roots());
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let config = Arc::new(config);
        let domain = "mozilla-modern.badssl.com";

        let (_, output) = get(config.clone(), domain, 443).await?;
        assert!(output.contains("<title>mozilla-modern.badssl.com</title>"));

        Ok(())
    })
}

fn all_roots() -> impl Iterator<Item = OwnedTrustAnchor> {
    webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|root| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            root.subject,
            root.spki,
            root.name_constraints,
        )
    })
}
