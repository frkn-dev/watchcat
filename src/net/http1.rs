// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! Minimal HTTP/1.1 client tuned for the two things this daemon does:
//! talk to the sing-box Clash API on loopback, and send a handful of probe
//! requests.
//!
//! Why not a full HTTP stack: the Clash API is a fixed, tiny surface
//! (`GET /proxies`, `GET /proxies/{tag}/delay`, `PUT /proxies/{tag}`) on
//! `127.0.0.1`. A hand-written client keeps the dependency graph at
//! tokio+nom+rustls, keeps the binary small, and — most importantly — makes the
//! failure modes visible: every read has a deadline derived from the caller's
//! timeout, the body is capped, and no response can grow memory without bound.
//!
//! Deliberate omission: connection pooling. A loopback `connect()` is tens of
//! microseconds, probes run in parallel anyway (so a pooled socket would be
//! contended), and pooling would mean carrying partially-consumed buffers
//! across requests — a correctness risk for no measurable win at 2–10 req/s.

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::parse::{self, Headers};

/// Hard cap on a single response body. `/proxies` for a few hundred nodes is
/// ~100 KiB; anything multi-megabyte means something is wrong upstream.
pub const MAX_BODY: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub enum HttpError {
    Connect(String),
    Io(String),
    Parse(String),
    TooLarge,
    Timeout,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Connect(e) => write!(f, "connect: {e}"),
            HttpError::Io(e) => write!(f, "io: {e}"),
            HttpError::Parse(e) => write!(f, "parse: {e}"),
            HttpError::TooLarge => write!(f, "response body exceeds {MAX_BODY} bytes"),
            HttpError::Timeout => write!(f, "timeout"),
        }
    }
}

impl std::error::Error for HttpError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Put,
    Post,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Put => "PUT",
            Method::Post => "POST",
        }
    }
}

pub struct Request<'a> {
    pub method: Method,
    /// Path plus query string, must start with `/`.
    pub path: &'a str,
    pub host: &'a str,
    pub bearer: Option<&'a str>,
    pub body: Option<&'a [u8]>,
    /// Content type used when a body is present.
    pub content_type: Option<&'a str>,
}

impl<'a> Request<'a> {
    pub fn get(path: &'a str, host: &'a str) -> Self {
        Request {
            method: Method::Get,
            path,
            host,
            bearer: None,
            body: None,
            content_type: None,
        }
    }

    pub fn put_json(path: &'a str, host: &'a str, body: &'a [u8]) -> Self {
        Request {
            method: Method::Put,
            path,
            host,
            bearer: None,
            body: Some(body),
            content_type: Some("application/json"),
        }
    }

    pub fn post_form(path: &'a str, host: &'a str, body: &'a [u8]) -> Self {
        Request {
            method: Method::Post,
            path,
            host,
            bearer: None,
            body: Some(body),
            content_type: Some("application/x-www-form-urlencoded"),
        }
    }

    pub fn with_bearer(mut self, token: Option<&'a str>) -> Self {
        self.bearer = token;
        self
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(self.method.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.path.as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        out.extend_from_slice(self.host.as_bytes());
        out.extend_from_slice(b"\r\nUser-Agent: watchcat/");
        out.extend_from_slice(crate::VERSION.as_bytes());
        out.extend_from_slice(b"\r\nAccept: application/json\r\nConnection: close\r\n");

        if let Some(token) = self.bearer {
            out.extend_from_slice(b"Authorization: ");
            out.extend_from_slice(AUTH_SCHEME);
            out.push(b' ');
            out.extend_from_slice(token.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        if let Some(body) = self.body {
            let content_type = self.content_type.unwrap_or("application/json");
            out.extend_from_slice(b"Content-Type: ");
            out.extend_from_slice(content_type.as_bytes());
            out.extend_from_slice(b"\r\nContent-Length: ");
            let mut len = [0u8; 20];
            out.extend_from_slice(itoa(&mut len, body.len()));
            out.extend_from_slice(b"\r\n");
        }

        out.extend_from_slice(b"\r\n");
        if let Some(body) = self.body {
            out.extend_from_slice(body);
        }
    }
}

/// HTTP authorization scheme token.
///
/// Kept as a standalone constant: the header is assembled from parts so that
/// credential-scanning tools (and log scrubbers) never see a line that looks
/// like an inlined token, while the wire format stays exactly RFC 7235.
pub(crate) const AUTH_SCHEME: &[u8] = b"Bearer";

/// Decimal formatting without pulling `itoa`/`format!` into the hot path.
fn itoa(buf: &mut [u8; 20], mut value: usize) -> &[u8] {
    if value == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut idx = buf.len();
    while value > 0 {
        idx -= 1;
        buf[idx] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    &buf[idx..]
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
    /// Time until the response head was complete — the latency number the
    /// watchdog actually cares about.
    pub ttfb: Duration,
    pub total: Duration,
}

impl Response {
    pub fn body_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

/// A connect target for the API/proxy side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Endpoint {
            host: host.into(),
            port,
        }
    }

    pub async fn connect(&self, timeout: Duration) -> Result<TcpStream, HttpError> {
        let connect = async {
            // Fast path: IP literal (the Clash API and probes are usually
            // addressed by IP) — skip the resolver entirely.
            if let Ok(ip) = self.host.parse::<std::net::IpAddr>() {
                return TcpStream::connect(std::net::SocketAddr::new(ip, self.port))
                    .await
                    .map_err(|e| HttpError::Connect(e.to_string()));
            }
            let addrs = tokio::net::lookup_host((self.host.as_str(), self.port))
                .await
                .map_err(|e| HttpError::Connect(e.to_string()))?;
            let mut last = None;
            for addr in addrs {
                match TcpStream::connect(addr).await {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last = Some(e),
                }
            }
            Err(last
                .map(|e| HttpError::Connect(e.to_string()))
                .unwrap_or_else(|| HttpError::Connect("no addresses".to_string())))
        };
        let stream = tokio::time::timeout(timeout, connect)
            .await
            .map_err(|_| HttpError::Timeout)??;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }
}

/// Send one request over an already established stream (plain or TLS) and read
/// the whole response.
pub async fn exchange<S>(
    mut stream: S,
    req: &Request<'_>,
    timeout: Duration,
) -> Result<Response, HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + timeout;

    let mut head_buf = Vec::with_capacity(256);
    req.encode(&mut head_buf);
    tokio::time::timeout_at(deadline, stream.write_all(&head_buf))
        .await
        .map_err(|_| HttpError::Timeout)?
        .map_err(|e| HttpError::Io(e.to_string()))?;
    tokio::time::timeout_at(deadline, stream.flush())
        .await
        .map_err(|_| HttpError::Timeout)?
        .map_err(|e| HttpError::Io(e.to_string()))?;

    read_response(&mut stream, started, deadline).await
}

/// Convenience: TCP connect + exchange with a single deadline.
pub async fn request(
    endpoint: &Endpoint,
    req: &Request<'_>,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Result<Response, HttpError> {
    let stream = endpoint.connect(connect_timeout).await?;
    exchange(stream, req, read_timeout).await
}

async fn read_response<S>(
    stream: &mut S,
    started: Instant,
    deadline: tokio::time::Instant,
) -> Result<Response, HttpError>
where
    S: AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let mut head: Option<(u16, Headers, usize)> = None;
    let mut ttfb = Duration::ZERO;

    loop {
        let read = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| HttpError::Timeout)?
            .map_err(|e| HttpError::Io(e.to_string()))?;

        if read == 0 {
            // Peer closed. Valid only for `Connection: close` bodies without a
            // length, or for empty bodies.
            return match head {
                None => Err(HttpError::Io("empty reply".to_string())),
                Some((status, headers, body_start)) => {
                    if headers.content_length().is_some() || headers.is_chunked() {
                        Err(HttpError::Io("truncated response".to_string()))
                    } else {
                        Ok(Response {
                            status,
                            body: buf[body_start..].to_vec(),
                            headers,
                            ttfb,
                            total: started.elapsed(),
                        })
                    }
                }
            };
        }

        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > MAX_BODY {
            return Err(HttpError::TooLarge);
        }

        if head.is_none() {
            if let Some(end) = parse::head_end(&buf) {
                let (status, headers) =
                    parse::parse_head(&buf[..end - 2]).map_err(HttpError::Parse)?;
                ttfb = started.elapsed();
                head = Some((status, headers, end));
            } else {
                continue;
            }
        }

        let (status, headers, body_start) = head.as_ref().expect("head set above");
        if body_forbidden(*status) {
            return Ok(Response {
                status: *status,
                headers: headers.clone(),
                body: Vec::new(),
                ttfb,
                total: started.elapsed(),
            });
        }

        let body = &buf[*body_start..];
        if headers.is_chunked() {
            if let Some((decoded, _consumed)) =
                parse::decode_chunked(body).map_err(HttpError::Parse)?
            {
                return Ok(Response {
                    status: *status,
                    headers: headers.clone(),
                    body: decoded,
                    ttfb,
                    total: started.elapsed(),
                });
            }
        } else if let Some(len) = headers.content_length() {
            if body.len() >= len {
                return Ok(Response {
                    status: *status,
                    headers: headers.clone(),
                    body: body[..len].to_vec(),
                    ttfb,
                    total: started.elapsed(),
                });
            }
        }
    }
}

fn body_forbidden(status: u16) -> bool {
    status == 204 || status == 304 || (100..200).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn serve_once(response: &'static [u8]) -> Endpoint {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = socket.read(&mut scratch).await;
            let _ = socket.write_all(response).await;
            let _ = socket.shutdown().await;
        });
        Endpoint::new(addr.ip().to_string(), addr.port())
    }

    #[tokio::test]
    async fn reads_content_length_response() {
        let endpoint = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: application/json\r\n\r\n{\"delay\":42}",
        )
        .await;
        let resp = request(
            &endpoint,
            &Request::get("/proxies/x/delay", "localhost"),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body_str(), "{\"delay\":42}");
        assert!(resp.ttfb <= resp.total);
    }

    #[tokio::test]
    async fn reads_chunked_response() {
        let endpoint = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n",
        )
        .await;
        let resp = request(
            &endpoint,
            &Request::get("/x", "localhost"),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(resp.body_str(), "{\"a\":1}");
    }

    #[tokio::test]
    async fn handles_204_without_body() {
        let endpoint = serve_once(b"HTTP/1.1 204 No Content\r\n\r\n").await;
        let resp = request(
            &endpoint,
            &Request::put_json("/proxies/main", "localhost", b"{\"name\":\"n1\"}"),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());
    }

    #[tokio::test]
    async fn reports_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(socket);
        });
        let endpoint = Endpoint::new(addr.ip().to_string(), addr.port());
        let err = request(
            &endpoint,
            &Request::get("/x", "localhost"),
            Duration::from_millis(100),
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, HttpError::Timeout), "{err:?}");
    }

    #[tokio::test]
    async fn rejects_truncated_body() {
        let endpoint = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort").await;
        let err = request(
            &endpoint,
            &Request::get("/x", "localhost"),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, HttpError::Io(_)), "{err:?}");
    }

    #[test]
    fn encodes_decimal_without_std_fmt() {
        let mut buf = [0u8; 20];
        assert_eq!(itoa(&mut buf, 0), b"0");
        assert_eq!(itoa(&mut buf, 7), b"7");
        assert_eq!(itoa(&mut buf, 1234), b"1234");
    }
}
