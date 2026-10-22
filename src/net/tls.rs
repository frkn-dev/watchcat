// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! TLS for probe and notifier connections.
//!
//! One process-wide `ClientConfig` (parsed roots + HTTP/1.1 ALPN) built on first
//! use. Certificate verification is always on: a probe that fails verification
//! is a real finding (broken handshake, MITM, expired cert), not something to
//! paper over. Snowflake and IP-SAN endpoints are both supported through
//! [`server_name`], which is why the `1.1.1.1` probe works.

use std::sync::{Arc, OnceLock};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

pub fn config() -> Arc<ClientConfig> {
    CONFIG
        .get_or_init(|| {
            // With only the `ring` feature enabled this installs ring as the
            // process default; ignore "already installed".
            let _ = rustls::crypto::ring::default_provider().install_default();

            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        })
        .clone()
}

/// Build a `ServerName` for an IP literal or a DNS name.
pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_string()).map_err(|e| format!("invalid server name {host}: {e}"))
}

pub async fn connect(stream: TcpStream, host: &str) -> Result<TlsStream<TcpStream>, String> {
    let name = server_name(host)?;
    let connector = TlsConnector::from(config());
    connector
        .connect(name, stream)
        .await
        .map_err(|e| format!("tls handshake: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ip_and_dns_names() {
        assert!(server_name("1.1.1.1").is_ok());
        assert!(server_name("api.openai.com").is_ok());
        assert!(server_name("2606:4700:4700::1111").is_ok());
        assert!(server_name("bad name with spaces").is_err());
    }

    /// Opt-in (network) check that the real handshake + HTTP/1.1 exchange
    /// works, including IP-SAN validation of `1.1.1.1`.
    ///
    /// `cargo test --lib -- --ignored real_tls_handshake`
    #[tokio::test]
    #[ignore = "requires outbound network access"]
    async fn real_tls_handshake_with_ip_san() {
        use std::time::Duration;
        use tokio::io::AsyncReadExt;

        let stream = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect("1.1.1.1:443"),
        )
        .await
        .expect("connect timeout")
        .expect("connect");

        let mut tls = connect(stream, "1.1.1.1").await.expect("tls handshake");

        let request = b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nUser-Agent: watchcat-test\r\nConnection: close\r\n\r\n";
        tokio::io::AsyncWriteExt::write_all(&mut tls, request)
            .await
            .expect("write request");

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut response))
            .await
            .expect("read timeout")
            .expect("read response");

        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("loc="), "trace body expected: {text}");
    }
}
