//! Minimal SOCKS5 client (RFC 1928, no auth, CONNECT only).
//!
//! Used by the end-to-end probe: it drives the *same* local proxy inbound that
//! client traffic uses, which is what makes it able to tell "the node died"
//! apart from "the local intercept/sing-box died".

use std::net::IpAddr;
use std::time::Duration;

use nom::bytes::complete::{tag, take};
use nom::combinator::map_res;
use nom::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::http1::{Endpoint, HttpError};

#[derive(Debug)]
pub enum SocksError {
    Connect(String),
    Protocol(String),
    Reply(u8),
    Timeout,
    Io(String),
}

impl std::fmt::Display for SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocksError::Connect(e) => write!(f, "socks connect: {e}"),
            SocksError::Protocol(e) => write!(f, "socks protocol: {e}"),
            SocksError::Reply(code) => write!(f, "socks reply {code} ({})", reply_text(*code)),
            SocksError::Timeout => write!(f, "socks timeout"),
            SocksError::Io(e) => write!(f, "socks io: {e}"),
        }
    }
}

impl std::error::Error for SocksError {}

fn reply_text(code: u8) -> &'static str {
    match code {
        0 => "succeeded",
        1 => "general failure",
        2 => "not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown",
    }
}

/// Where the proxy should connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Domain name — resolved by the proxy, not locally (remote DNS).
    Domain(String, u16),
    Ip(IpAddr, u16),
}

impl Target {
    pub fn parse(host: &str, port: u16) -> Target {
        match host.parse::<IpAddr>() {
            Ok(ip) => Target::Ip(ip, port),
            Err(_) => Target::Domain(host.to_string(), port),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Target::Domain(host, _) => host.clone(),
            Target::Ip(ip, _) => ip.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Target::Domain(_, port) | Target::Ip(_, port) => *port,
        }
    }
}

/// Open a TCP stream to `target` through the SOCKS5 proxy at `proxy`.
pub async fn connect(
    proxy: &Endpoint,
    target: &Target,
    timeout: Duration,
) -> Result<TcpStream, SocksError> {
    let stream = proxy.connect(timeout).await.map_err(|e| match e {
        HttpError::Timeout => SocksError::Timeout,
        HttpError::Connect(e) => SocksError::Connect(e),
        other => SocksError::Io(other.to_string()),
    })?;

    let mut stream = stream;
    let handshake = async {
        // Greeting: VER=5, NMETHODS=1, METHODS=[0x00 no-auth]
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|e| SocksError::Io(e.to_string()))?;

        let mut reply = [0u8; 2];
        stream
            .read_exact(&mut reply)
            .await
            .map_err(|e| SocksError::Io(e.to_string()))?;
        if reply[0] != 0x05 {
            return Err(SocksError::Protocol(format!(
                "unexpected version {}",
                reply[0]
            )));
        }
        if reply[1] != 0x00 {
            return Err(SocksError::Protocol(format!(
                "proxy requires auth method {:#04x}",
                reply[1]
            )));
        }

        let mut request = Vec::with_capacity(32);
        request.extend_from_slice(&[0x05, 0x01, 0x00]); // VER, CONNECT, RSV
        match target {
            Target::Ip(IpAddr::V4(ip), _) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            Target::Ip(IpAddr::V6(ip), _) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
            Target::Domain(host, _) => {
                if host.len() > 255 {
                    return Err(SocksError::Protocol("domain too long".to_string()));
                }
                request.push(0x03);
                request.push(host.len() as u8);
                request.extend_from_slice(host.as_bytes());
            }
        }
        request.extend_from_slice(&target.port().to_be_bytes());
        stream
            .write_all(&request)
            .await
            .map_err(|e| SocksError::Io(e.to_string()))?;

        let mut head = [0u8; 4];
        stream
            .read_exact(&mut head)
            .await
            .map_err(|e| SocksError::Io(e.to_string()))?;
        let (_rest, (rep, atyp)) =
            parse_reply_head(&head).map_err(|_| SocksError::Protocol("bad reply".to_string()))?;
        if rep != 0x00 {
            return Err(SocksError::Reply(rep));
        }
        // BND.ADDR (variable) + BND.PORT (2 bytes) — read and discard.
        let addr_len = match atyp {
            0x01 => 4,
            0x03 => {
                let mut len = [0u8; 1];
                stream
                    .read_exact(&mut len)
                    .await
                    .map_err(|e| SocksError::Io(e.to_string()))?;
                len[0] as usize
            }
            0x04 => 16,
            other => {
                return Err(SocksError::Protocol(format!(
                    "unsupported address type {other:#04x}"
                )))
            }
        };
        let mut bind = vec![0u8; addr_len + 2];
        stream
            .read_exact(&mut bind)
            .await
            .map_err(|e| SocksError::Io(e.to_string()))?;
        Ok(())
    };

    tokio::time::timeout(timeout, handshake)
        .await
        .map_err(|_| SocksError::Timeout)??;
    Ok(stream)
}

/// Parse the 4-byte reply prefix: VER, REP, RSV, ATYP.
fn parse_reply_head(input: &[u8]) -> nom::IResult<&[u8], (u8, u8)> {
    let (rest, _) = tag([0x05u8].as_slice()).parse(input)?;
    let (rest, rep) = map_res(take(1usize), |b: &[u8]| Ok::<u8, ()>(b[0])).parse(rest)?;
    let (rest, _) = take(1usize).parse(rest)?;
    let (rest, atyp) = map_res(take(1usize), |b: &[u8]| Ok::<u8, ()>(b[0])).parse(rest)?;
    Ok((rest, (rep, atyp)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connects_through_mock_socks_proxy() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            socket.write_all(&[0x05, 0x00]).await.unwrap();

            let mut head = [0u8; 4];
            socket.read_exact(&mut head).await.unwrap();
            assert_eq!(head, [0x05, 0x01, 0x00, 0x03]);
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await.unwrap();
            let mut host = vec![0u8; len[0] as usize + 2];
            socket.read_exact(&mut host).await.unwrap();

            // REP=0, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            socket.write_all(b"pong").await.unwrap();
        });

        let proxy = Endpoint::new(addr.ip().to_string(), addr.port());
        let mut stream = connect(
            &proxy,
            &Target::Domain("1.1.1.1".to_string(), 443),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn surfaces_connection_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            let _ = socket.read_exact(&mut greeting).await;
            let _ = socket.write_all(&[0x05, 0x00]).await;
            let mut head = [0u8; 4];
            let _ = socket.read_exact(&mut head).await;
            let _ = socket
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
        });

        let proxy = Endpoint::new(addr.ip().to_string(), addr.port());
        let err = connect(
            &proxy,
            &Target::Ip("203.0.113.1".parse().unwrap(), 443),
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SocksError::Reply(5)), "{err:?}");
    }

    #[test]
    fn parses_reply_head() {
        let (_rest, (rep, atyp)) = parse_reply_head(&[0x05, 0x00, 0x00, 0x03]).unwrap();
        assert_eq!(rep, 0);
        assert_eq!(atyp, 0x03);
    }
}
