//! Репортёр должен реально отправлять событие в api — проверяем на живом
//! TCP-сокете, а не на моках: контракт (путь, токен, тело) ломается молча,
//! если его не проверять по проводу.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use watchcat::config::ReportingConfig;
use watchcat::log::{Level, Logs};
use watchcat::notify::{EventBus, NotifyEvent};
use watchcat::report::{ReportStats, Reporter};

#[tokio::test]
async fn reporter_posts_switch_to_api() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();

    // Поднимаем «api»: принимаем один запрос и отвечаем 200.
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 8192];
        let mut received = Vec::new();
        // Читаем заголовки и тело (Content-Length).
        loop {
            let n = socket.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
            if let Some(pos) = find_body_start(&received) {
                let headers = String::from_utf8_lossy(&received[..pos]).to_lowercase();
                let len: usize = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                if received.len() >= pos + 4 + len {
                    break;
                }
            }
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("write");
        String::from_utf8_lossy(&received).to_string()
    });

    let cfg = ReportingConfig {
        enabled: true,
        url: format!("http://127.0.0.1:{port}"),
        token: Some("test-token".to_string()),
        node: "msk-tw.frkn.org".to_string(),
        timeout_ms: 3_000,
        attempts: 1,
    };
    let stats = Arc::new(ReportStats::default());
    let handle = tokio::runtime::Handle::current();
    let (tx, _handle) =
        Reporter::spawn(&handle, cfg, Logs::for_tests(Level::Error), stats.clone()).expect("spawn");
    let bus = EventBus::new(vec![tx]);

    bus.send(NotifyEvent::Switch {
        group: "fr-exit".to_string(),
        from: Some("ufo-fr49".to_string()),
        to: "ufo-fr50".to_string(),
        reason: "active_degraded".to_string(),
        latency_ms: 120,
        api_roundtrip_ms: Some(15),
    });

    let request = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("api должен получить запрос за 5 с")
        .expect("server task");

    // путь и авторизация
    assert!(
        request.starts_with("POST /v1/node/watchcat/event"),
        "путь: {}",
        request.lines().next().unwrap_or("")
    );
    assert!(
        request.to_lowercase().contains("authorization: bearer test-token"),
        "нет Bearer-токена: {request}"
    );
    // тело
    let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
    let json: serde_json::Value = serde_json::from_str(body).expect("тело должно быть JSON");
    assert_eq!(json["hostname"], "msk-tw.frkn.org");
    assert_eq!(json["group"], "fr-exit");
    assert_eq!(json["kind"], "switch");
    assert_eq!(json["from"], "ufo-fr49");
    assert_eq!(json["to"], "ufo-fr50");
    assert_eq!(json["reason"], "active_degraded");
    assert!(
        json["at"].as_str().unwrap_or("").ends_with('Z'),
        "время в RFC3339 UTC: {:?}",
        json["at"]
    );

    // дождаться учёта отправки
    for _ in 0..50 {
        if stats.sent.load(Ordering::Relaxed) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(stats.sent.load(Ordering::Relaxed), 1);
    assert_eq!(stats.failed.load(Ordering::Relaxed), 0);
}

/// Репортёр без включённого reporting не создаётся: шина остаётся пустой.
#[tokio::test]
async fn disabled_reporting_creates_no_sink() {
    let cfg = ReportingConfig {
        enabled: false,
        url: "http://127.0.0.1:1".to_string(),
        token: None,
        node: "n".to_string(),
        timeout_ms: 100,
        attempts: 1,
    };
    let handle = tokio::runtime::Handle::current();
    let spawned = Reporter::spawn(
        &handle,
        cfg,
        Logs::for_tests(Level::Error),
        Arc::new(ReportStats::default()),
    );
    assert!(spawned.is_none());
    assert!(EventBus::new(vec![]).is_empty());
}

fn find_body_start(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Регрессия 0.4.0: `main` синхронный, и `tokio::spawn` вне рантайма паникует
/// («no reactor running»), роняя процесс на старте. Теперь задача стартует
/// через Handle, полученный снаружи, — проверяем ровно этот сценарий.
#[test]
fn spawn_from_sync_context_does_not_panic() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let handle = runtime.handle().clone();

    let cfg = ReportingConfig {
        enabled: true,
        url: "http://127.0.0.1:9".to_string(),
        token: Some("t".to_string()),
        node: "n".to_string(),
        timeout_ms: 50,
        attempts: 1,
    };
    // Вне block_on: раньше здесь был паник.
    let spawned = Reporter::spawn(&handle, cfg, Logs::for_tests(Level::Error), Arc::new(ReportStats::default()));
    assert!(spawned.is_some(), "канал создаётся и в синхронном контексте");
}
