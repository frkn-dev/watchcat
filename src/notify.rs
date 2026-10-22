// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! Optional Telegram notifications.
//!
//! Runs as a separate task behind a small bounded channel: the failover loop
//! must never block on somebody's phone. If the channel is full or the network
//! is down, notifications are dropped and counted — routing correctness does not
//! depend on them.
//!
//! Two guards against alert storms:
//!
//! * a minimum interval between messages (`telegram.min_interval_ms`), and
//! * suppression of an identical message repeated within [`DEDUPE_WINDOW_MS`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::config::TelegramConfig;
use crate::log::Logs;
use crate::net::http1::{self, Endpoint, Method, Request};
use crate::net::tls;
use crate::parse::{encode_component, Url};
use serde_json::json;

pub const DEDUPE_WINDOW_MS: u64 = 60_000;
pub const CHANNEL_CAPACITY: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyEvent {
    Switch {
        from: Option<String>,
        to: String,
        reason: String,
        latency_ms: u32,
        api_roundtrip_ms: Option<u64>,
    },
    Quarantine {
        tag: String,
        reason: String,
        quarantine_ms: u64,
        fails: u32,
    },
    Recovered {
        tag: String,
    },
    NoHealthy {
        active: Option<String>,
    },
    InterceptBroken {
        detail: String,
    },
}

impl NotifyEvent {
    pub fn render(&self) -> String {
        match self {
            NotifyEvent::Switch {
                from,
                to,
                reason,
                latency_ms,
                api_roundtrip_ms,
            } => {
                let from = from.as_deref().unwrap_or("-");
                let api = api_roundtrip_ms
                    .map(|ms| format!(" · api {ms} ms"))
                    .unwrap_or_default();
                format!("[SWITCH] {from} → {to}\nreason: {reason}\nlatency: {latency_ms} ms{api}")
            }
            NotifyEvent::Quarantine {
                tag,
                reason,
                quarantine_ms,
                fails,
            } => format!(
                "[QUARANTINE] {tag}\nreason: {reason} ({fails} consecutive)\nfor: {} s",
                quarantine_ms / 1000
            ),
            NotifyEvent::Recovered { tag } => format!("[RECOVERED] {tag} is selectable again"),
            NotifyEvent::NoHealthy { active } => format!(
                "[OUTAGE] no healthy outbound\nactive: {}",
                active.as_deref().unwrap_or("none")
            ),
            NotifyEvent::InterceptBroken { detail } => format!(
                "[INTERCEPT] local proxy path is broken, switching nodes will not help\n{detail}"
            ),
        }
    }

    /// Coarse class used for dedupe: two different nodes quarantining are two
    /// different events, but repeating the same one is noise.
    fn fingerprint(&self) -> String {
        self.render()
    }
}

/// Tracks rate limiting and dedupe. Pure so it can be unit tested.
pub struct Throttle {
    min_interval_ms: u64,
    last_sent_ms: u64,
    last_fingerprint: String,
    last_fingerprint_ms: u64,
}

impl Throttle {
    pub fn new(min_interval_ms: u64) -> Throttle {
        Throttle {
            min_interval_ms,
            last_sent_ms: 0,
            last_fingerprint: String::new(),
            last_fingerprint_ms: 0,
        }
    }

    /// `Some(text)` when the message should be sent now.
    pub fn check(&mut self, event: &NotifyEvent, now_ms: u64) -> Option<String> {
        let text = event.render();
        let fingerprint = event.fingerprint();

        if !fingerprint.is_empty()
            && fingerprint == self.last_fingerprint
            && now_ms.saturating_sub(self.last_fingerprint_ms) < DEDUPE_WINDOW_MS
        {
            return None;
        }
        if now_ms.saturating_sub(self.last_sent_ms) < self.min_interval_ms {
            return None;
        }
        self.last_sent_ms = now_ms;
        self.last_fingerprint = fingerprint;
        self.last_fingerprint_ms = now_ms;
        Some(text)
    }
}

pub struct Notifier {
    cfg: TelegramConfig,
    endpoint: Endpoint,
    host_header: String,
    tls: bool,
    path_prefix: String,
    logs: Logs,
    delivered: Arc<AtomicU64>,
}

impl Notifier {
    pub fn new(
        cfg: TelegramConfig,
        logs: Logs,
        delivered: Arc<AtomicU64>,
    ) -> Result<Notifier, String> {
        let url = Url::parse(&cfg.api_base)?;
        Ok(Notifier {
            endpoint: Endpoint::new(url.host.clone(), url.port),
            host_header: url.host_header(),
            tls: url.is_tls(),
            path_prefix: url.path.trim_end_matches('/').to_string(),
            cfg,
            logs,
            delivered,
        })
    }

    /// Send one message. The bot token lives in the URL path, so it is never
    /// logged: only the HTTP status and the API's `ok` flag are.
    pub async fn send(&self, text: &str) -> Result<(), String> {
        let token = self.cfg.bot_token.as_deref().ok_or("missing bot token")?;
        let chat_id = self.cfg.chat_id.as_deref().ok_or("missing chat id")?;
        let path = format!(
            "{}/bot{}/sendMessage",
            self.path_prefix,
            encode_component(token)
        );
        let body = format!(
            "chat_id={}&disable_web_page_preview=true&text={}",
            encode_component(chat_id),
            encode_component(text)
        );

        let request = Request {
            method: Method::Post,
            path: &path,
            host: &self.host_header,
            bearer: None,
            body: Some(body.as_bytes()),
            content_type: Some("application/x-www-form-urlencoded"),
        };

        let timeout = Duration::from_secs(10);
        let response = if self.tls {
            let stream = self
                .endpoint
                .connect(timeout)
                .await
                .map_err(|e| e.to_string())?;
            let stream = tls::connect(stream, &self.host_header).await?;
            http1::exchange(stream, &request, timeout).await
        } else {
            http1::request(&self.endpoint, &request, timeout, timeout).await
        }
        .map_err(|e| e.to_string())?;

        let ok = response.status == 200;
        if !ok {
            return Err(format!("telegram http {}", response.status));
        }
        self.delivered.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn spawn(
        cfg: TelegramConfig,
        logs: Logs,
        delivered: Arc<AtomicU64>,
    ) -> Option<(mpsc::Sender<NotifyEvent>, tokio::task::JoinHandle<()>)> {
        if !cfg.enabled {
            return None;
        }
        let notifier = match Notifier::new(cfg.clone(), logs.clone(), delivered) {
            Ok(notifier) => notifier,
            Err(err) => {
                logs.error("telegram_init_failed", json!({ "error": err }));
                return None;
            }
        };
        let (tx, mut rx) = mpsc::channel::<NotifyEvent>(CHANNEL_CAPACITY);
        let handle = tokio::spawn(async move {
            let mut throttle = Throttle::new(notifier.cfg.min_interval_ms);
            while let Some(event) = rx.recv().await {
                let now = crate::clock::mono_ms();
                let Some(text) = throttle.check(&event, now) else {
                    continue;
                };
                for attempt in 0..2 {
                    match notifier.send(&text).await {
                        Ok(()) => {
                            notifier
                                .logs
                                .info("telegram_sent", json!({ "bytes": text.len() }));
                            break;
                        }
                        Err(err) if attempt == 0 => {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            let _ = err;
                        }
                        Err(err) => {
                            notifier
                                .logs
                                .warn("telegram_failed", json!({ "error": err }));
                        }
                    }
                }
            }
        });
        Some((tx, handle))
    }
}

/// Fire-and-forget send: never blocks the caller, drops on a full queue.
pub fn send_async(tx: &Option<mpsc::Sender<NotifyEvent>>, event: NotifyEvent) {
    if let Some(tx) = tx {
        let _ = tx.try_send(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_switch_message() {
        let text = NotifyEvent::Switch {
            from: Some("node-01-fr-vless".into()),
            to: "node-02-de-hysteria".into(),
            reason: "active_failed".into(),
            latency_ms: 42,
            api_roundtrip_ms: Some(3),
        }
        .render();
        assert!(text.contains("[SWITCH] node-01-fr-vless → node-02-de-hysteria"));
        assert!(text.contains("reason: active_failed"));
        assert!(text.contains("api 3 ms"));
    }

    #[test]
    fn throttle_dedupes_and_rate_limits() {
        let event = NotifyEvent::Recovered {
            tag: "node-03".into(),
        };
        let mut throttle = Throttle::new(1_000);
        assert!(throttle.check(&event, 10_000).is_some());
        // Same message inside the dedupe window: suppressed.
        assert!(throttle.check(&event, 10_500).is_none());
        // Different message but inside the rate-limit window: suppressed.
        let other = NotifyEvent::Quarantine {
            tag: "node-04".into(),
            reason: "failed".into(),
            quarantine_ms: 300_000,
            fails: 2,
        };
        assert!(throttle.check(&other, 10_600).is_none());
        // After the rate limit, allowed.
        assert!(throttle.check(&other, 11_500).is_some());
    }

    #[test]
    fn dedupe_expires() {
        let event = NotifyEvent::NoHealthy {
            active: Some("node-01".into()),
        };
        let mut throttle = Throttle::new(0);
        assert!(throttle.check(&event, 1_000).is_some());
        assert!(throttle.check(&event, 2_000).is_none());
        assert!(throttle
            .check(&event, 1_000 + DEDUPE_WINDOW_MS + 1)
            .is_some());
    }

    #[test]
    fn renders_outage_and_intercept() {
        let outage = NotifyEvent::NoHealthy { active: None }.render();
        assert!(outage.contains("[OUTAGE]"));
        assert!(outage.contains("active: none"));
        let intercept = NotifyEvent::InterceptBroken {
            detail: "socks refused".into(),
        }
        .render();
        assert!(intercept.contains("[INTERCEPT]"));
    }

    #[tokio::test]
    async fn sends_to_plain_http_endpoint() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")
                .await;
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let cfg = TelegramConfig {
            enabled: true,
            bot_token: Some("123:abc".into()),
            chat_id: Some("42".into()),
            api_base: format!("http://{}:{}", addr.ip(), addr.port()),
            min_interval_ms: 0,
        };
        let delivered = Arc::new(AtomicU64::new(0));
        let notifier = Notifier::new(
            cfg,
            Logs::for_tests(crate::log::Level::Debug),
            delivered.clone(),
        )
        .unwrap();
        notifier.send("[SWITCH] a → b").await.unwrap();
        assert_eq!(delivered.load(Ordering::Relaxed), 1);

        let request = handle.await.unwrap();
        assert!(
            request.starts_with("POST /bot123%3Aabc/sendMessage "),
            "{request}"
        );
        assert!(request.contains("chat_id=42"));
        assert!(request.contains("text=%5BSWITCH%5D%20a%20%E2%86%92%20b"));
    }

    #[tokio::test]
    async fn surfaces_non_200() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        let cfg = TelegramConfig {
            enabled: true,
            bot_token: Some("bad".into()),
            chat_id: Some("1".into()),
            api_base: format!("http://{}:{}", addr.ip(), addr.port()),
            min_interval_ms: 0,
        };
        let notifier = Notifier::new(
            cfg,
            Logs::for_tests(crate::log::Level::Debug),
            Arc::new(AtomicU64::new(0)),
        )
        .unwrap();
        assert!(notifier.send("x").await.is_err());
    }
}
