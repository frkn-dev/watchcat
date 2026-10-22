// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! Clash API client (the sing-box control surface).
//!
//! Only four endpoints are used:
//!
//! | Method | Path                              | Purpose                        |
//! |--------|-----------------------------------|--------------------------------|
//! | GET    | `/proxies/{selector}`             | current `now` + member list    |
//! | GET    | `/proxies/{tag}/delay?url=&timeout=` | per-outbound latency probe  |
//! | PUT    | `/proxies/{selector}`             | switch the active outbound     |
//! | GET    | `/version`                        | startup fingerprint            |
//!
//! Everything is on loopback and plain HTTP (sing-box's Clash API has no TLS);
//! `config::validate` rejects an `https://` base URL to avoid the illusion of
//! transport security.

use std::borrow::Cow;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::config::ApiConfig;
use crate::net::http1::{self, Endpoint, HttpError, Request};
use crate::parse::{encode_component, Url};

#[derive(Debug)]
pub enum ClashError {
    Transport(String),
    Timeout,
    Status { status: u16, message: String },
    Json(String),
    NotFound(String),
}

impl std::fmt::Display for ClashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClashError::Transport(e) => write!(f, "transport: {e}"),
            ClashError::Timeout => write!(f, "timeout"),
            ClashError::Status { status, message } => write!(f, "http {status}: {message}"),
            ClashError::Json(e) => write!(f, "json: {e}"),
            ClashError::NotFound(tag) => write!(f, "proxy {tag} not found"),
        }
    }
}

impl std::error::Error for ClashError {}

impl From<HttpError> for ClashError {
    fn from(err: HttpError) -> Self {
        match err {
            HttpError::Timeout => ClashError::Timeout,
            HttpError::Parse(e) => ClashError::Json(e),
            other => ClashError::Transport(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorState {
    /// Currently selected outbound, if the group reports one.
    pub now: Option<String>,
    /// Members, in the order sing-box reports them.
    pub all: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchResult {
    pub status: u16,
    pub roundtrip_ms: u64,
}

#[derive(Debug, Deserialize)]
struct SelectorResponse<'a> {
    #[serde(default, borrow)]
    now: Option<Cow<'a, str>>,
    #[serde(default, borrow)]
    all: Option<Vec<Cow<'a, str>>>,
    #[serde(default, rename = "type", borrow)]
    kind: Option<Cow<'a, str>>,
}

#[derive(Debug, Deserialize)]
struct DelayResponse<'a> {
    #[serde(default)]
    delay: Option<u32>,
    #[serde(default, borrow)]
    message: Option<Cow<'a, str>>,
}

#[derive(Debug, Deserialize)]
struct MessageResponse<'a> {
    #[serde(default, borrow)]
    message: Option<Cow<'a, str>>,
}

#[derive(Debug, Deserialize)]
struct VersionResponse<'a> {
    #[serde(default, borrow)]
    version: Option<Cow<'a, str>>,
}

#[derive(Clone)]
pub struct ClashClient {
    origin: String,
    endpoint: Endpoint,
    host_header: String,
    secret: Option<String>,
    connect_timeout: Duration,
    timeout: Duration,
}

impl ClashClient {
    pub fn new(api: &ApiConfig) -> Result<ClashClient, String> {
        let url = Url::parse(&api.base_url)?;
        let host_header = url.host_header();
        Ok(ClashClient {
            origin: api.base_url.clone(),
            endpoint: Endpoint::new(url.host.clone(), url.port),
            host_header,
            secret: api.secret.clone(),
            connect_timeout: Duration::from_millis(api.connect_timeout_ms),
            timeout: Duration::from_millis(api.timeout_ms),
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn base_url(&self) -> &str {
        &self.origin
    }

    async fn get(&self, path: &str) -> Result<http1::Response, ClashError> {
        let req = Request::get(path, &self.host_header).with_bearer(self.secret.as_deref());
        http1::request(&self.endpoint, &req, self.connect_timeout, self.timeout)
            .await
            .map_err(ClashError::from)
    }

    async fn put(&self, path: &str, body: &[u8]) -> Result<http1::Response, ClashError> {
        let req =
            Request::put_json(path, &self.host_header, body).with_bearer(self.secret.as_deref());
        http1::request(&self.endpoint, &req, self.connect_timeout, self.timeout)
            .await
            .map_err(ClashError::from)
    }

    /// Read the state of a selector group.
    pub async fn selector(&self, tag: &str) -> Result<SelectorState, ClashError> {
        let path = format!("/proxies/{}", encode_component(tag));
        let response = self.get(&path).await?;
        if response.status == 404 {
            return Err(ClashError::NotFound(tag.to_string()));
        }
        if !(200..300).contains(&response.status) {
            return Err(ClashError::Status {
                status: response.status,
                message: message_of(&response.body),
            });
        }
        let parsed: SelectorResponse =
            serde_json::from_slice(&response.body).map_err(|e| ClashError::Json(e.to_string()))?;
        let all = parsed
            .all
            .ok_or_else(|| {
                ClashError::Json(format!(
                    "proxy {tag} is not a selector (type {}) — PUT would be rejected",
                    parsed.kind.as_deref().unwrap_or("unknown")
                ))
            })?
            .into_iter()
            .map(|tag| tag.into_owned())
            .collect();
        Ok(SelectorState {
            now: parsed
                .now
                .map(|now| now.into_owned())
                .filter(|s| !s.is_empty()),
            all,
        })
    }

    /// Switch the selector to `name`. Measurements are taken around the HTTP
    /// round-trip so the audit log can show real control-plane latency.
    pub async fn select(&self, selector: &str, name: &str) -> Result<SwitchResult, ClashError> {
        let body = format!("{{\"name\":{}}}", json_string(name));
        let path = format!("/proxies/{}", encode_component(selector));
        let started = Instant::now();
        let response = self.put(&path, body.as_bytes()).await?;
        let roundtrip_ms = started.elapsed().as_millis() as u64;
        if !(200..300).contains(&response.status) {
            return Err(ClashError::Status {
                status: response.status,
                message: message_of(&response.body),
            });
        }
        Ok(SwitchResult {
            status: response.status,
            roundtrip_ms,
        })
    }

    /// Ask sing-box to measure this outbound against `url`.
    ///
    /// The returned value is sing-box's own measurement (it dials the probe
    /// itself), so no extra sockets are involved on our side.
    pub async fn delay(&self, tag: &str, url: &str, timeout_ms: u64) -> Result<u32, ClashError> {
        let path = format!(
            "/proxies/{}/delay?url={}&timeout={}",
            encode_component(tag),
            encode_component(url),
            timeout_ms
        );
        let response = self.get(&path).await?;
        if response.status == 404 {
            return Err(ClashError::NotFound(tag.to_string()));
        }
        if !(200..300).contains(&response.status) {
            return Err(ClashError::Status {
                status: response.status,
                message: message_of(&response.body),
            });
        }
        let parsed: DelayResponse =
            serde_json::from_slice(&response.body).map_err(|e| ClashError::Json(e.to_string()))?;
        match parsed.delay {
            Some(delay) => Ok(delay),
            None => Err(ClashError::Json(
                parsed
                    .message
                    .map(|m| m.into_owned())
                    .unwrap_or_else(|| "delay response without `delay`".to_string()),
            )),
        }
    }

    pub async fn version(&self) -> Result<String, ClashError> {
        let response = self.get("/version").await?;
        if !(200..300).contains(&response.status) {
            return Err(ClashError::Status {
                status: response.status,
                message: message_of(&response.body),
            });
        }
        let parsed: VersionResponse =
            serde_json::from_slice(&response.body).map_err(|e| ClashError::Json(e.to_string()))?;
        Ok(parsed.version.map(|v| v.into_owned()).unwrap_or_default())
    }
}

/// Encode a JSON string literal without pulling `serde_json::to_string` into
/// the PUT path (the payload is one short name).
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn message_of(body: &[u8]) -> String {
    if body.is_empty() {
        return String::new();
    }
    match serde_json::from_slice::<MessageResponse>(body) {
        Ok(parsed) => parsed
            .message
            .map(|m| m.into_owned())
            .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned()),
        Err(_) => String::from_utf8_lossy(body).chars().take(200).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::http1::AUTH_SCHEME;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serve a script of `(status, body)` responses, one per connection, and
    /// record the request lines the client sent.
    async fn mock(
        responses: Vec<(u16, String)>,
    ) -> (ApiConfig, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut seen = Vec::new();
            for (status, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 2048];
                let n = socket.read(&mut buf).await.unwrap();
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                seen.push(text.lines().next().unwrap_or_default().to_string());
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
            seen
        });
        (
            ApiConfig {
                base_url: format!("http://{}:{}", addr.ip(), addr.port()),
                secret: Some("s3cr3t".to_string()),
                connect_timeout_ms: 500,
                timeout_ms: 2_000,
            },
            handle,
        )
    }

    #[tokio::test]
    async fn reads_selector_state() {
        let (api, handle) = mock(vec![(
            200,
            "{\"type\":\"Selector\",\"now\":\"node-01-fr-vless\",\"all\":[\"node-01-fr-vless\"]}"
                .to_string(),
        )])
        .await;
        let client = ClashClient::new(&api).unwrap();
        let state = client.selector("main-outbound").await.unwrap();
        assert_eq!(state.now.as_deref(), Some("node-01-fr-vless"));
        assert_eq!(state.all, vec!["node-01-fr-vless".to_string()]);
        let seen = handle.await.unwrap();
        assert!(
            seen[0].starts_with("GET /proxies/main-outbound "),
            "{:?}",
            seen[0]
        );
    }

    #[tokio::test]
    async fn selector_membership_missing_is_an_error() {
        let (api, _handle) =
            mock(vec![(200, "{\"type\":\"Vless\",\"now\":\"\"}".to_string())]).await;
        let client = ClashClient::new(&api).unwrap();
        let err = client.selector("node-01").await.unwrap_err();
        assert!(matches!(err, ClashError::Json(_)), "{err:?}");
    }

    #[tokio::test]
    async fn reads_delay_and_reports_api_error() {
        let (api, _handle) = mock(vec![
            (200, "{\"delay\":42}".to_string()),
            (504, "{\"message\":\"context deadline\"}".to_string()),
        ])
        .await;
        let client = ClashClient::new(&api).unwrap();
        assert_eq!(
            client
                .delay("node-01", "https://1.1.1.1/cdn-cgi/trace", 2000)
                .await
                .unwrap(),
            42
        );
        let err = client
            .delay("node-01", "https://1.1.1.1/cdn-cgi/trace", 2000)
            .await
            .unwrap_err();
        match err {
            ClashError::Status { status, message } => {
                assert_eq!(status, 504);
                assert!(message.contains("deadline"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn put_switch_reports_roundtrip_and_errors() {
        let (api, handle) = mock(vec![
            (204, String::new()),
            (400, "{\"message\":\"not a member\"}".to_string()),
        ])
        .await;
        let client = ClashClient::new(&api).unwrap();
        let result = client
            .select("main-outbound", "node-02-de-hysteria")
            .await
            .unwrap();
        assert_eq!(result.status, 204);
        assert!(result.roundtrip_ms < 2_000);

        let err = client.select("main-outbound", "nope").await.unwrap_err();
        assert!(
            matches!(err, ClashError::Status { status: 400, .. }),
            "{err:?}"
        );

        let seen = handle.await.unwrap();
        assert!(
            seen[0].starts_with("PUT /proxies/main-outbound "),
            "{:?}",
            seen[0]
        );
    }

    #[tokio::test]
    async fn missing_proxy_is_not_found() {
        let (api, _handle) = mock(vec![(404, String::new())]).await;
        let client = ClashClient::new(&api).unwrap();
        assert!(matches!(
            client.selector("nope").await.unwrap_err(),
            ClashError::NotFound(_)
        ));
    }

    #[test]
    fn json_string_escapes_hostile_names() {
        assert_eq!(json_string("node-01"), "\"node-01\"");
        assert_eq!(json_string("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
        assert_eq!(json_string("x\u{1}"), "\"x\\u0001\"");
    }

    #[tokio::test]
    async fn sends_bearer_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let _ = socket
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await;
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let api = ApiConfig {
            base_url: format!("http://{}:{}", addr.ip(), addr.port()),
            secret: Some("top-secret".to_string()),
            ..ApiConfig::default()
        };
        let client = ClashClient::new(&api).unwrap();
        client.select("main-outbound", "node-01").await.unwrap();
        let request = handle.await.unwrap();
        assert!(request.contains("Authorization: "));
        assert!(request.contains(std::str::from_utf8(AUTH_SCHEME).unwrap()));
        assert!(request.contains("top-secret"));
        assert!(!request.contains("Authorization: ***"));
    }
}
