// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! End-to-end failover test: real binaries, real sockets, no sing-box.
//!
//! `mock-clash` plays sing-box (Clash API + a SOCKS5 inbound), `watchcat` runs
//! as a normal child process with a real config file. The assertions are made
//! against artifacts an operator would actually look at:
//!
//! * the audit trail (did traffic move, from where to where, why),
//! * the mock server's stdout (`PUT /proxies/…` really arrived),
//! * the daemon's own JSON log.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Collects a child's stdout lines in the background.
fn capture(stream: impl std::io::Read + Send + 'static) -> Arc<Mutex<Vec<String>>> {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = lines.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            sink.lock().unwrap().push(line);
        }
    });
    lines
}

fn wait_for_line(lines: &Arc<Mutex<Vec<String>>>, prefix: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(found) = lines
            .lock()
            .unwrap()
            .iter()
            .find(|line| line.starts_with(prefix))
            .cloned()
        {
            return found;
        }
        if Instant::now() > deadline {
            panic!(
                "timed out waiting for {prefix}; captured: {:?}",
                lines.lock().unwrap()
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for<F: Fn() -> bool>(what: &str, timeout: Duration, condition: F) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {what}");
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "watchcat-it-{tag}-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Stack {
    _mock: Guard,
    mock_lines: Arc<Mutex<Vec<String>>>,
    api_url: String,
    socks_url: String,
    dir: PathBuf,
    audit: PathBuf,
}

fn start_mock(extra_args: &[&str], tag: &str) -> Stack {
    let dir = temp_dir(tag);
    let mut command = Command::new(env!("CARGO_BIN_EXE_mock-clash"));
    command.args(["--api", "127.0.0.1:0", "--socks", "127.0.0.1:0"]);
    command.args(extra_args);
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().expect("spawn mock-clash");
    let stdout = child.stdout.take().expect("mock stdout");
    let mock_lines = capture(stdout);
    let mock = Guard(child);

    let api_line = wait_for_line(&mock_lines, "MOCK_READY api=", Duration::from_secs(10));
    let socks_line = wait_for_line(&mock_lines, "MOCK_READY socks=", Duration::from_secs(10));
    let api_url = api_line.trim_start_matches("MOCK_READY api=").to_string();
    let socks_url = socks_line
        .trim_start_matches("MOCK_READY socks=")
        .to_string();
    let audit = dir.join("routes.jsonl");

    Stack {
        _mock: mock,
        mock_lines,
        api_url,
        socks_url,
        dir,
        audit,
    }
}

impl Stack {
    fn write_config(&self, extra: &str) -> PathBuf {
        let config = format!(
            r#"
api:
  base_url: "{api}"
  secret: "test-secret"
  connect_timeout_ms: 300
  timeout_ms: 1000
selector:
  tag: main-outbound
  adopt_external_changes: true
probe:
  interval_ms: 150
  fast_interval_ms: 100
  timeout_ms: 400
  concurrency: 10
  method: both
  base_url: "http://1.1.1.1/cdn-cgi/trace"
  critical_url: "http://api.openai.com/v1/models"
  critical_every_ticks: 1
  accept_status: [200, 204, 401]
  block_status: [403, 451]
  e2e_proxy: "{socks}"
  e2e_enabled: true
policy:
  fail_threshold: 2
  quarantine_ms: 1500
  min_switch_interval_ms: 0
  recovery_probes: 1
  stale_ms: 5000
logging:
  level: debug
  format: json
  stdout: true
  audit_path: "{audit}"
metrics:
  enabled: false
  path: "{metrics}"
telegram:
  enabled: false
{extra}
"#,
            api = self.api_url,
            socks = self.socks_url,
            audit = self.audit.display(),
            metrics = self.dir.join("metrics.prom").display(),
            extra = extra,
        );
        let path = self.dir.join("config.yaml");
        std::fs::write(&path, config).unwrap();
        path
    }

    fn run_daemon(&self, config: &PathBuf, timeout: Duration) -> Vec<String> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_watchcat"))
            .arg("--config")
            .arg(config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn watchcat");
        let stdout = capture(child.stdout.take().unwrap());
        let stderr = child.stderr.take().unwrap();
        let _ = capture(stderr);
        let _guard = Guard(child);

        std::thread::sleep(timeout);
        let lines = stdout.lock().unwrap().clone();
        lines
    }

    fn audit_lines(&self) -> Vec<serde_json::Value> {
        let text = std::fs::read_to_string(&self.audit).unwrap_or_default();
        text.lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}

#[test]
fn failing_active_node_is_quarantined_and_traffic_moves() {
    let stack = start_mock(&["--fail", "node-01-fr-vless"], "failover");
    let config = stack.write_config("");

    let lines = stack.run_daemon(&config, Duration::from_secs(4));

    // The daemon started and reached the API.
    assert!(
        lines
            .iter()
            .any(|line| line.contains("\"event\":\"start\"")),
        "no start event in {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.contains("\"event\":\"tick\"")),
        "no tick event in {lines:?}"
    );

    // The switch arrived at the (mock) sing-box.
    let switch_line = wait_for_line(&stack.mock_lines, "MOCK_SWITCH", Duration::from_secs(2));
    assert!(
        switch_line.contains("node-01-fr-vless -> node-02-de-hysteria"),
        "unexpected switch: {switch_line}"
    );

    // And it is on the audit trail with a reason and the failing node's counter.
    let audit = stack.audit_lines();
    let switch = audit
        .iter()
        .find(|record| record["event"] == "route_switch")
        .unwrap_or_else(|| panic!("no route_switch record in {audit:?}"));
    assert_eq!(switch["from"], "node-01-fr-vless");
    assert_eq!(switch["to"], "node-02-de-hysteria");
    assert_eq!(switch["reason"], "active_failed");
    assert_eq!(switch["fails"], 2);
    assert_eq!(switch["api_ok"], true);
    assert_eq!(switch["selector"], "main-outbound");

    let quarantine = audit
        .iter()
        .find(|record| record["event"] == "quarantine_enter")
        .unwrap_or_else(|| panic!("no quarantine record in {audit:?}"));
    assert_eq!(quarantine["to"], "node-01-fr-vless");
    assert_eq!(quarantine["reason"], "failed");
    assert_eq!(quarantine["fails"], 2);

    // The daemon noticed the end-to-end probe path working (mock SOCKS).
    assert!(
        lines
            .iter()
            .any(|line| line.contains("\"event\":\"intercept_probe_ok\"")),
        "expected a successful end-to-end probe in {lines:?}"
    );

    let _ = std::fs::remove_dir_all(&stack.dir);
}

#[test]
fn dry_run_reports_the_switch_without_touching_the_selector() {
    let stack = start_mock(&["--fail", "node-01-fr-vless"], "dryrun");
    let config = stack.write_config("");

    let mut child = Command::new(env!("CARGO_BIN_EXE_watchcat"))
        .arg("--config")
        .arg(&config)
        .arg("--dry-run")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn watchcat");
    let stdout = capture(child.stdout.take().unwrap());
    let _guard = Guard(child);

    wait_for("dry_run switch record", Duration::from_secs(6), || {
        stack
            .audit_lines()
            .iter()
            .any(|record| record["trigger"] == "dry_run")
    });

    // Nothing was sent to the selector.
    assert!(
        !stack
            .mock_lines
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.starts_with("MOCK_SWITCH")),
        "dry-run must not PUT: {:?}",
        stack.mock_lines.lock().unwrap()
    );
    assert!(stdout
        .lock()
        .unwrap()
        .iter()
        .any(|line| line.contains("switch_dry_run")));

    let _ = std::fs::remove_dir_all(&stack.dir);
}

#[test]
fn once_mode_probes_the_pool_and_exits_cleanly() {
    let stack = start_mock(&[], "once");
    let config = stack.write_config("");

    let output = Command::new(env!("CARGO_BIN_EXE_watchcat"))
        .arg("--config")
        .arg(&config)
        .arg("--once")
        .output()
        .expect("run watchcat --once");

    assert!(output.status.success(), "status: {:?}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"event\":\"once_complete\""), "{stdout}");
    // 10 nodes × (base + critical) probes.
    assert!(stdout.contains("\"probed\":20"), "{stdout}");
    assert!(stdout.contains("\"switched\":null"), "{stdout}");
    // No switch while everything is healthy.
    assert!(!stack
        .mock_lines
        .lock()
        .unwrap()
        .iter()
        .any(|line| line.starts_with("MOCK_SWITCH")));

    let _ = std::fs::remove_dir_all(&stack.dir);
}

#[test]
fn unreachable_api_changes_nothing_and_exits_2() {
    let dir = temp_dir("api-down");
    // Bind and drop to obtain a definitely closed port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let audit = dir.join("routes.jsonl");
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            r#"
api:
  base_url: "http://127.0.0.1:{port}"
  connect_timeout_ms: 200
  timeout_ms: 200
selector:
  tag: main-outbound
logging:
  level: debug
  format: json
  stdout: true
  audit_path: "{}"
metrics:
  enabled: false
  path: "{}"
"#,
            audit.display(),
            dir.join("metrics.prom").display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_watchcat"))
        .arg("--config")
        .arg(&config)
        .arg("--once")
        .output()
        .expect("run watchcat --once");

    assert_eq!(output.status.code(), Some(2), "status: {:?}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"event\":\"clash_api_unavailable\""),
        "{stdout}"
    );
    // Nothing is written when the API is down: no state, no audit record.
    let audit_text = std::fs::read_to_string(&audit).unwrap_or_default();
    assert!(audit_text.is_empty(), "audit must stay empty: {audit_text}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_mode_validates_config_without_network() {
    let dir = temp_dir("check");
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        "api:\n  base_url: \"http://127.0.0.1:9090\"\nselector:\n  tag: main-outbound\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_watchcat"))
        .arg("--config")
        .arg(&path)
        .arg("--check")
        .output()
        .expect("run watchcat --check");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("config OK"), "{stdout}");
    assert!(stdout.contains("main-outbound"), "{stdout}");

    // A broken config must fail loudly.
    std::fs::write(&path, "policy:\n  fail_threshold: 0\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_watchcat"))
        .arg("--config")
        .arg(&path)
        .arg("--check")
        .output()
        .expect("run watchcat --check");
    assert!(!output.status.success());
    let _ = std::fs::remove_dir_all(&dir);
}
