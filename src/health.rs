// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! Health probes and their classification.
//!
//! Two independent probe paths, because they answer different questions:
//!
//! 1. **Clash delay API** (`GET /proxies/{tag}/delay`) — sing-box dials the
//!    outbound itself and reports milliseconds. Zero extra sockets here, exact
//!    same dialer as real traffic, and it works for every member in parallel.
//!    This is what feeds latency scoring.
//! 2. **End-to-end probe** (SOCKS5 → TLS → HTTP through the local proxy
//!    inbound) — proves the whole path a client would take works: inbound,
//!    routing, selector, outbound. Used for the active node only.
//!
//! The combination is what makes the diagnosis unambiguous: Clash delay OK +
//! end-to-end failing ⇒ *our* intercept/inbound is broken, switching nodes will
//! not help. See `docs/DETECTION.md`.

use std::sync::Arc;
use std::time::Duration;

use crate::clash::{ClashClient, ClashError};
use crate::config::ProbeConfig;
use crate::net::http1::{self, Endpoint, Request};
use crate::net::{socks5, tls};
use crate::parse::{self, TraceInfo, Url};
use crate::state::Outcome;

/// Status-code policy, configurable but with a defensible default.
#[derive(Debug, Clone)]
pub struct Tiers {
    pub accept: Vec<u16>,
    pub block: Vec<u16>,
}

impl Tiers {
    pub fn from_config(cfg: &ProbeConfig) -> Tiers {
        Tiers {
            accept: cfg.accept_status.clone(),
            block: cfg.block_status.clone(),
        }
    }

    /// Classify an HTTP status. Order matters: an explicit `accept` entry wins,
    /// then `block`, then 5xx/429/garbage become `Inconclusive` (reachable, but
    /// not the node's fault — e.g. OpenAI returning 500 or rate limiting).
    pub fn classify(&self, status: u16, latency_ms: u32) -> Outcome {
        if self.accept.contains(&status) {
            return Outcome::Ok { latency_ms, status };
        }
        if self.block.contains(&status) {
            return Outcome::Blocked { status, latency_ms };
        }
        Outcome::Inconclusive { status }
    }
}

/// Which probe produced a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVia {
    ClashDelay,
    EndToEnd,
}

impl ProbeVia {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeVia::ClashDelay => "clash_delay",
            ProbeVia::EndToEnd => "end_to_end",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub tag: String,
    pub via: ProbeVia,
    pub url: String,
    /// Whether this probe targets the blocking-sensitive endpoint.
    pub critical: bool,
    pub outcome: Outcome,
    pub trace: Option<TraceInfo>,
}

/// Map a Clash API delay error message to an outcome.
///
/// Substring matching (no regex) over the lowercase message: sing-box proxies
/// the dialer's error text, which is stable enough (`timeout`,
/// `connection refused`, `no route to host`, `context deadline exceeded`,
/// `EOF`, `tls: …`).
pub fn classify_delay_error(message: &str) -> Outcome {
    let text = message.to_ascii_lowercase();
    let timeout = text.contains("timeout") || text.contains("deadline");
    let transport = text.contains("refused")
        || text.contains("reset by peer")
        || text.contains("no route to host")
        || text.contains("network is unreachable")
        || text.contains("eof")
        || text.contains("handshake failure")
        || text.starts_with("tls:")
        || text.contains("dial tcp");

    if timeout {
        Outcome::Timeout
    } else if transport {
        Outcome::Transport
    } else {
        Outcome::ApiError(message.to_string())
    }
}

pub struct ProbeEngine {
    clash: Arc<ClashClient>,
    tiers: Tiers,
    timeout: Duration,
    delay_timeout_ms: u64,
    concurrency: usize,
    base: Url,
    critical: Option<Url>,
    proxy: Endpoint,
    e2e_enabled: bool,
}

impl ProbeEngine {
    pub fn new(clash: Arc<ClashClient>, cfg: &ProbeConfig) -> Result<ProbeEngine, String> {
        let base = Url::parse(&cfg.base_url)?;
        let critical = match &cfg.critical_url {
            Some(url) => Some(Url::parse(url)?),
            None => None,
        };
        let proxy_url = Url::parse(&cfg.e2e_proxy)?;
        Ok(ProbeEngine {
            clash,
            tiers: Tiers::from_config(cfg),
            timeout: Duration::from_millis(cfg.timeout_ms),
            delay_timeout_ms: cfg.timeout_ms,
            concurrency: cfg.concurrency.max(1),
            base,
            critical,
            proxy: Endpoint::new(proxy_url.host.clone(), proxy_url.port),
            e2e_enabled: cfg.e2e_enabled,
        })
    }

    pub fn base_url(&self) -> &Url {
        &self.base
    }

    pub fn critical_url(&self) -> Option<&Url> {
        self.critical.as_ref()
    }

    pub fn e2e_enabled(&self) -> bool {
        self.e2e_enabled
    }

    /// Probe every tag through the Clash delay API.
    ///
    /// Requests run in bounded parallel chunks (`probe.concurrency`), and the
    /// returned vector is in the same order as `tags` so the audit/metrics
    /// output is stable between runs.
    pub async fn probe_members(&self, tags: &[String], include_critical: bool) -> Vec<ProbeReport> {
        let mut reports = Vec::with_capacity(tags.len());
        for chunk in tags.chunks(self.concurrency) {
            let mut tasks = Vec::with_capacity(chunk.len());
            for tag in chunk {
                let tag = tag.clone();
                let clash = self.clash.clone();
                let base = self.base.clone();
                let critical = if include_critical {
                    self.critical.clone()
                } else {
                    None
                };
                let delay_timeout_ms = self.delay_timeout_ms;
                tasks.push(tokio::spawn(async move {
                    let mut out = Vec::with_capacity(2);
                    let base_url = base.to_url_string();
                    out.push(ProbeReport {
                        tag: tag.clone(),
                        via: ProbeVia::ClashDelay,
                        url: base_url.clone(),
                        critical: false,
                        outcome: delay_outcome(
                            clash.delay(&tag, &base_url, delay_timeout_ms).await,
                        ),
                        trace: None,
                    });
                    if let Some(critical) = critical {
                        let critical_url = critical.to_url_string();
                        out.push(ProbeReport {
                            tag: tag.clone(),
                            via: ProbeVia::ClashDelay,
                            url: critical_url.clone(),
                            critical: true,
                            outcome: delay_outcome(
                                clash.delay(&tag, &critical_url, delay_timeout_ms).await,
                            ),
                            trace: None,
                        });
                    }
                    out
                }));
            }
            for task in tasks {
                if let Ok(mut chunk_reports) = task.await {
                    reports.append(&mut chunk_reports);
                }
                // A panicked probe task is a missed sample, not a dead pool:
                // the affected node simply ages out as stale.
            }
        }
        reports
    }

    /// End-to-end probe of `url` through the local proxy inbound.
    pub async fn probe_e2e(&self, tag: &str, url: &Url) -> ProbeReport {
        let (outcome, trace) = match self.e2e(url).await {
            Ok((status, latency_ms, trace)) => (self.tiers.classify(status, latency_ms), trace),
            Err(outcome) => (outcome, None),
        };
        ProbeReport {
            tag: tag.to_string(),
            via: ProbeVia::EndToEnd,
            url: url.path.clone(),
            critical: self.critical.as_ref().map(|c| c == url).unwrap_or(false),
            outcome,
            trace,
        }
    }

    async fn e2e(&self, url: &Url) -> Result<(u16, u32, Option<TraceInfo>), Outcome> {
        let started = std::time::Instant::now();
        let target = socks5::Target::parse(&url.host, url.port);
        let host_header = url.host_header();
        let request = Request::get(&url.path, &host_header);

        let stream = socks5::connect(&self.proxy, &target, self.timeout)
            .await
            .map_err(|err| match err {
                socks5::SocksError::Timeout => Outcome::Timeout,
                socks5::SocksError::Reply(code) => Outcome::ApiError(format!("socks reply {code}")),
                _ => Outcome::Transport,
            })?;

        let response = if url.is_tls() {
            let tls_stream = tls::connect(stream, &url.host)
                .await
                .map_err(|_| Outcome::Transport)?;
            http1::exchange(tls_stream, &request, self.timeout).await
        } else {
            http1::exchange(stream, &request, self.timeout).await
        }
        .map_err(|err| match err {
            http1::HttpError::Timeout => Outcome::Timeout,
            _ => Outcome::Transport,
        })?;

        let latency_ms = response.ttfb.as_millis() as u32;
        let trace = parse::trace_info(&String::from_utf8_lossy(&response.body))
            .ok()
            .map(|(_, info)| info)
            .filter(|info| info.ip.is_some() || info.loc.is_some());

        let _ = started;
        Ok((response.status, latency_ms, trace))
    }
}

/// `ClashError` → `Outcome`. A 504 is Clash's "the outbound did not answer in
/// time", which is exactly a probe timeout.
fn delay_outcome(result: Result<u32, ClashError>) -> Outcome {
    match result {
        Ok(delay) => Outcome::Ok {
            latency_ms: delay,
            status: 0,
        },
        Err(ClashError::Timeout) => Outcome::Timeout,
        Err(ClashError::Status { status: 504, .. }) => Outcome::Timeout,
        Err(ClashError::Status { message, .. }) => classify_delay_error(&message),
        Err(ClashError::Transport(_)) => Outcome::Transport,
        Err(ClashError::NotFound(tag)) => Outcome::ApiError(format!("proxy {tag} not found")),
        Err(other) => Outcome::ApiError(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProbeConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn tiers() -> Tiers {
        Tiers::from_config(&ProbeConfig::default())
    }

    #[test]
    fn classifies_accept_block_and_inconclusive() {
        let tiers = tiers();
        assert!(matches!(tiers.classify(200, 10), Outcome::Ok { .. }));
        assert!(matches!(tiers.classify(401, 10), Outcome::Ok { .. }));
        assert!(matches!(tiers.classify(403, 10), Outcome::Blocked { .. }));
        assert!(matches!(tiers.classify(451, 10), Outcome::Blocked { .. }));
        assert!(matches!(
            tiers.classify(502, 10),
            Outcome::Inconclusive { .. }
        ));
        assert!(matches!(
            tiers.classify(429, 10),
            Outcome::Inconclusive { .. }
        ));
    }

    #[test]
    fn accept_wins_over_block_for_overlap() {
        let tiers = Tiers {
            accept: vec![403],
            block: vec![403],
        };
        assert!(matches!(tiers.classify(403, 1), Outcome::Ok { .. }));
    }

    #[test]
    fn classifies_delay_errors_without_regex() {
        assert_eq!(
            classify_delay_error("context deadline exceeded"),
            Outcome::Timeout
        );
        assert_eq!(
            classify_delay_error("dial tcp 1.2.3.4:443: i/o timeout"),
            Outcome::Timeout
        );
        assert_eq!(
            classify_delay_error("connect: connection refused"),
            Outcome::Transport
        );
        assert_eq!(
            classify_delay_error("read: connection reset by peer"),
            Outcome::Transport
        );
        assert_eq!(
            classify_delay_error("tls: handshake failure"),
            Outcome::Transport
        );
        match classify_delay_error("unsupported proxy type") {
            Outcome::ApiError(message) => assert!(message.contains("unsupported")),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Minimal SOCKS5 server: accepts one CONNECT, then answers the tunneled
    /// HTTP request with `status`.
    async fn mock_socks(status: u16, body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            socket.write_all(&[0x05, 0x00]).await.unwrap();

            let mut head = [0u8; 4];
            socket.read_exact(&mut head).await.unwrap();
            let atyp = head[3];
            if atyp == 0x03 {
                let mut len = [0u8; 1];
                socket.read_exact(&mut len).await.unwrap();
                let mut host = vec![0u8; len[0] as usize + 2];
                socket.read_exact(&mut host).await.unwrap();
            } else {
                let mut rest = vec![0u8; 6];
                socket.read_exact(&mut rest).await.unwrap();
            }
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
                .await
                .unwrap();

            let mut request = vec![0u8; 1024];
            let _ = socket.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 {} X\r\nContent-Length: {}\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
        port
    }

    fn engine_with_proxy(port: u16) -> ProbeEngine {
        let api = crate::config::ApiConfig::default();
        let clash = Arc::new(ClashClient::new(&api).unwrap());
        let cfg = ProbeConfig {
            e2e_proxy: format!("socks5://127.0.0.1:{port}"),
            timeout_ms: 1_000,
            ..ProbeConfig::default()
        };
        ProbeEngine::new(clash, &cfg).unwrap()
    }

    #[tokio::test]
    async fn e2e_probe_parses_trace_through_socks() {
        let port = mock_socks(200, "fl=1\nip=203.0.113.9\nloc=DE\nwarp=off\ncolo=FRA\n").await;
        let engine = engine_with_proxy(port);
        let url = Url::parse("http://1.1.1.1/cdn-cgi/trace").unwrap();
        let report = engine.probe_e2e("node-01", &url).await;
        assert!(
            matches!(report.outcome, Outcome::Ok { status: 200, .. }),
            "{:?}",
            report.outcome
        );
        let trace = report.trace.expect("trace parsed");
        assert_eq!(trace.loc.as_deref(), Some("DE"));
        assert_eq!(trace.ip.as_deref(), Some("203.0.113.9"));
    }

    #[tokio::test]
    async fn e2e_probe_flags_geo_block() {
        let port = mock_socks(403, "blocked").await;
        let engine = engine_with_proxy(port);
        let url = Url::parse("http://api.openai.com/v1/models").unwrap();
        let report = engine.probe_e2e("node-01", &url).await;
        assert!(matches!(
            report.outcome,
            Outcome::Blocked { status: 403, .. }
        ));
    }

    #[tokio::test]
    async fn e2e_probe_reports_transport_failure_when_proxy_is_down() {
        // Bind and immediately drop to get a closed port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let engine = engine_with_proxy(port);
        let url = Url::parse("http://1.1.1.1/cdn-cgi/trace").unwrap();
        let report = engine.probe_e2e("node-01", &url).await;
        assert!(
            matches!(report.outcome, Outcome::Transport),
            "{:?}",
            report.outcome
        );
    }

    #[test]
    fn probe_engine_rejects_bad_urls() {
        let clash = Arc::new(ClashClient::new(&crate::config::ApiConfig::default()).unwrap());
        let cfg = ProbeConfig {
            base_url: "nonsense".into(),
            ..ProbeConfig::default()
        };
        assert!(ProbeEngine::new(clash, &cfg).is_err());
    }
}
