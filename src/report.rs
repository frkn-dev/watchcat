//! Отправка событий в api.
//!
//! Раньше единственным получателем был Telegram прямо с ноды: там лежал токен
//! бота и там же решалось, что считать важным. Это неправильная сторона —
//! демон должен говорить «случилось вот это», а «кого оповещать и как часто»
//! решает api, у которого есть реестр нод и история.
//!
//! Поэтому здесь простой репортёр: событие -> JSON -> POST в api. Токен
//! сервиса, имя ноды и адрес берутся из `reporting` конфига. Ошибки не
//! блокируют цикл проб: очередь ограничена, при переполнении событие теряется
//! (лучше потерять одно уведомление, чем сломать управление выходами).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::mpsc;

use crate::config::ReportingConfig;
use crate::log::Logs;
use crate::net::http1::{self, Endpoint, Method, Request};
use crate::net::tls;
use crate::notify::NotifyEvent;
use crate::parse::Url;

/// Размер очереди: события редкие (переключения — единицы в сутки), но при
/// шторме не хотим ни блокировать пробы, ни терять последние.
pub const QUEUE_CAPACITY: usize = 64;

/// Счётчики для метрик.
#[derive(Default)]
pub struct ReportStats {
    pub sent: AtomicU64,
    pub failed: AtomicU64,
    pub dropped: AtomicU64,
}

pub struct Reporter {
    cfg: ReportingConfig,
    endpoint: Endpoint,
    host_header: String,
    tls: bool,
    path_prefix: String,
    logs: Logs,
    stats: Arc<ReportStats>,
}

impl std::fmt::Debug for Reporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reporter")
            .field("node", &self.cfg.node)
            .field("url", &self.cfg.url)
            .finish()
    }
}

impl Reporter {
    pub fn new(cfg: ReportingConfig, logs: Logs, stats: Arc<ReportStats>) -> Result<Reporter, String> {
        let url = Url::parse(&cfg.url)?;
        Ok(Reporter {
            endpoint: Endpoint::new(url.host.clone(), url.port),
            host_header: url.host_header(),
            tls: url.is_tls(),
            path_prefix: format!("{}/v1/node/watchcat/event", url.path.trim_end_matches('/')),
            stats,
            cfg,
            logs,
        })
    }

    /// Тело запроса: ровно то, что ждёт api.
    pub fn payload(&self, event: &NotifyEvent, at_ms: u64) -> serde_json::Value {
        let (kind, from, to, reason, detail) = match event {
            NotifyEvent::Switch {
                from,
                to,
                reason,
                latency_ms,
                api_roundtrip_ms,
                ..
            } => {
                let api = api_roundtrip_ms
                    .map(|ms| format!(", api {ms} ms"))
                    .unwrap_or_default();
                (
                    "switch",
                    from.clone(),
                    Some(to.clone()),
                    Some(reason.clone()),
                    Some(format!("latency {latency_ms} ms{api}")),
                )
            }
            NotifyEvent::NoHealthy { active, .. } => {
                ("no_healthy", active.clone(), None, None, None)
            }
            NotifyEvent::InterceptBroken { detail, .. } => {
                ("intercept_broken", None, None, None, Some(detail.clone()))
            }
            NotifyEvent::Quarantine {
                tag,
                reason,
                quarantine_ms,
                fails,
                ..
            } => (
                "quarantine",
                None,
                Some(tag.clone()),
                Some(reason.clone()),
                Some(format!("{fails} подряд, {} с", quarantine_ms / 1000)),
            ),
            NotifyEvent::Recovered { tag, .. } => ("recovered", None, Some(tag.clone()), None, None),
        };

        json!({
            "hostname": self.cfg.node,
            "group": event.group(),
            "kind": kind,
            "from": from,
            "to": to,
            "reason": reason,
            "detail": detail,
            "at": crate::clock::rfc3339_ms(at_ms),
        })
    }

    /// Одна попытка отправки. `Ok(())` — api принял (200).
    pub async fn send(&self, body: &serde_json::Value) -> Result<(), String> {
        let text = serde_json::to_string(body).map_err(|e| e.to_string())?;
        let timeout = Duration::from_millis(self.cfg.timeout_ms);
        let bearer = self.cfg.token.clone().unwrap_or_default();
        let request = Request {
            method: Method::Post,
            path: &self.path_prefix,
            host: &self.host_header,
            bearer: Some(&bearer),
            body: Some(text.as_bytes()),
            content_type: Some("application/json"),
        };

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

        match response.status {
            200..=299 => Ok(()),
            // 4xx — наша вина (кривой конфиг/контракт), ретраить бессмысленно.
            code => Err(format!("api http {code}")),
        }
    }

    /// Отправляет с ретраями и пишет результат в журнал.
    pub async fn send_with_retry(&self, body: &serde_json::Value) {
        let attempts = self.cfg.attempts.max(1);
        let mut delay = Duration::from_millis(500);
        for attempt in 1..=attempts {
            match self.send(body).await {
                Ok(()) => {
                    self.stats.sent.fetch_add(1, Ordering::Relaxed);
                    self.logs.info(
                        "api_report_sent",
                        json!({ "kind": body.get("kind"), "attempt": attempt }),
                    );
                    return;
                }
                Err(err) => {
                    let last = attempt == attempts;
                    if last {
                        self.stats.failed.fetch_add(1, Ordering::Relaxed);
                        self.logs.warn(
                            "api_report_failed",
                            json!({
                                "kind": body.get("kind"),
                                "attempts": attempts,
                                "error": err,
                            }),
                        );
                        return;
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(10));
                }
            }
        }
    }

    /// Запускает фоновую отправку. `None` — reporting выключен.
    pub fn spawn(
        cfg: ReportingConfig,
        logs: Logs,
        stats: Arc<ReportStats>,
    ) -> Option<(mpsc::Sender<NotifyEvent>, tokio::task::JoinHandle<()>)> {
        if !cfg.enabled {
            return None;
        }
        let reporter = match Reporter::new(cfg, logs.clone(), stats) {
            Ok(reporter) => reporter,
            Err(err) => {
                logs.error("api_report_init_failed", json!({ "error": err }));
                return None;
            }
        };
        let (tx, mut rx) = mpsc::channel::<NotifyEvent>(QUEUE_CAPACITY);
        let handle = tokio::spawn(async move {
            // Шлём по одному событию за раз: переключения редкие, а пачка
            // одновременных соединений к api при шторме никому не нужна.
            let mut pending: VecDeque<NotifyEvent> = VecDeque::new();
            while let Some(event) = rx.recv().await {
                pending.push_back(event);
                // Забираем всё, что уже накопилось, но не ждём второго события:
                // иначе одиночное переключение висело бы в очереди до следующего.
                while let Ok(more) = rx.try_recv() {
                    if pending.len() >= QUEUE_CAPACITY {
                        reporter.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    pending.push_back(more);
                }
                while let Some(event) = pending.pop_front() {
                    let at = crate::clock::unix_ms();
                    let body = reporter.payload(&event, at);
                    reporter.send_with_retry(&body).await;
                }
            }
        });
        Some((tx, handle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ReportingConfig as Cfg;

    fn cfg() -> Cfg {
        Cfg {
            enabled: true,
            url: "http://127.0.0.1:3000".to_string(),
            token: Some("service-token".to_string()),
            node: "msk-tw.frkn.org".to_string(),
            timeout_ms: 2_000,
            attempts: 2,
        }
    }

    fn reporter() -> Reporter {
        Reporter::new(cfg(), Logs::for_tests(crate::log::Level::Error), Arc::new(ReportStats::default()))
            .expect("reporter")
    }

    #[test]
    fn switch_payload_matches_contract() {
        let r = reporter();
        let event = NotifyEvent::Switch {
            group: "fr-exit".into(),
            from: Some("ufo-fr49".into()),
            to: "ufo-fr50".into(),
            reason: "active_degraded".into(),
            latency_ms: 120,
            api_roundtrip_ms: Some(15),
        };
        let body = r.payload(&event, 1_700_000_000_000);
        assert_eq!(body["hostname"], "msk-tw.frkn.org");
        assert_eq!(body["group"], "fr-exit");
        assert_eq!(body["kind"], "switch");
        assert_eq!(body["from"], "ufo-fr49");
        assert_eq!(body["to"], "ufo-fr50");
        assert_eq!(body["reason"], "active_degraded");
        assert_eq!(body["at"], "2023-11-14T22:13:20.000Z");
    }

    #[test]
    fn no_healthy_has_no_target() {
        let r = reporter();
        let event = NotifyEvent::NoHealthy {
            group: "bt-exit".into(),
            active: Some("ufo-fr52".into()),
        };
        let body = r.payload(&event, 0);
        assert_eq!(body["kind"], "no_healthy");
        assert_eq!(body["from"], "ufo-fr52");
        assert!(body["to"].is_null());
    }

    #[test]
    fn token_is_not_logged_in_debug() {
        let text = format!("{:?}", cfg());
        assert!(!text.contains("service-token"), "токен не должен попадать в Debug");
    }
}
