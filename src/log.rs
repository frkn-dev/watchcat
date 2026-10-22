// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! Structured logging plus the dedicated route-change audit trail.
//!
//! Two sinks, deliberately separate:
//!
//! * **application log** (stdout, JSON lines or text) — probes, decisions,
//!   errors, timing. High volume, rotated by the supervisor process manager
//!   (`systemd`/`journald`).
//! * **audit log** (`logging.audit_path`, JSONL, append-only) — *only* events
//!   that change or could change where traffic exits: switches, quarantine
//!   enter/exit, active-node adoption, no-healthy-node outages. This file is the
//!   answer to "who moved my traffic, when and why"; it is written with a single
//!   `write` per record so a crash cannot interleave half-lines.
//!
//! See `docs/ROUTING-AUDIT.md` for the schema and `jq` recipes.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::clock;
use crate::config::{LogFormat, LoggingConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl Level {
    pub fn parse(text: &str) -> Option<Level> {
        match text.trim().to_ascii_lowercase().as_str() {
            "error" | "err" => Some(Level::Error),
            "warn" | "warning" => Some(Level::Warn),
            "info" => Some(Level::Info),
            "debug" => Some(Level::Debug),
            "trace" => Some(Level::Trace),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
            Level::Trace => "trace",
        }
    }
}

struct Sink {
    level: Level,
    format: LogFormat,
    stdout: bool,
    audit: Option<AuditFile>,
    buf: Vec<u8>,
}

struct AuditFile {
    writer: BufWriter<File>,
    path: String,
    fsync: bool,
    broken: bool,
}

/// Cheap-to-clone logging handle shared by the supervisor, the probe tasks and
/// the notifier. A `Mutex` per line is far cheaper than the formatting work it
/// protects.
#[derive(Clone)]
pub struct Logs {
    sink: Arc<Mutex<Sink>>,
}

impl Logs {
    pub fn init(cfg: &LoggingConfig, level: Level) -> std::io::Result<Logs> {
        let audit = match &cfg.audit_path {
            Some(path) => Some(AuditFile::open(path, cfg.fsync_audit)?),
            None => None,
        };
        Ok(Logs {
            sink: Arc::new(Mutex::new(Sink {
                level,
                format: cfg.format,
                stdout: cfg.stdout,
                audit,
                buf: Vec::with_capacity(512),
            })),
        })
    }

    /// In-memory logger for tests (no file, no stdout).
    pub fn for_tests(level: Level) -> Logs {
        Logs {
            sink: Arc::new(Mutex::new(Sink {
                level,
                format: LogFormat::Json,
                stdout: false,
                audit: None,
                buf: Vec::new(),
            })),
        }
    }

    pub fn level(&self) -> Level {
        self.sink.lock().map(|s| s.level).unwrap_or(Level::Info)
    }

    pub fn enabled(&self, level: Level) -> bool {
        level <= self.level()
    }

    pub fn log(&self, level: Level, event: &str, fields: Value) {
        if !self.enabled(level) {
            return;
        }
        let Ok(mut sink) = self.sink.lock() else {
            return;
        };
        sink.emit(level, event, fields);
    }

    pub fn error(&self, event: &str, fields: Value) {
        self.log(Level::Error, event, fields);
    }

    pub fn warn(&self, event: &str, fields: Value) {
        self.log(Level::Warn, event, fields);
    }

    pub fn info(&self, event: &str, fields: Value) {
        self.log(Level::Info, event, fields);
    }

    pub fn debug(&self, event: &str, fields: Value) {
        self.log(Level::Debug, event, fields);
    }

    /// Append one record to the audit trail. Failed writes are reported once,
    /// then the audit sink disables itself: a broken disk must not take the
    /// failover guard down with it, but it must be loud.
    pub fn audit(&self, record: &AuditRecord) {
        let Ok(mut sink) = self.sink.lock() else {
            return;
        };
        let mut line = Vec::with_capacity(256);
        if serde_json::to_writer(&mut line, record).is_err() {
            return;
        }
        line.push(b'\n');

        // Take the audit file out of the borrow before reporting a write
        // failure, so the error can be emitted through the same sink.
        let failure = {
            let Some(audit) = sink.audit.as_mut() else {
                return;
            };
            if audit.broken {
                return;
            }
            match audit.write(&line) {
                Ok(()) => None,
                Err(err) => {
                    audit.broken = true;
                    Some((audit.path.clone(), err.to_string()))
                }
            }
        };
        if let Some((path, error)) = failure {
            sink.emit(
                Level::Error,
                "audit_write_failed",
                json!({ "path": path, "error": error }),
            );
        }
    }

    /// Only used by tests and the mock harness.
    pub fn audit_path(&self) -> Option<String> {
        self.sink
            .lock()
            .ok()
            .and_then(|s| s.audit.as_ref().map(|a| a.path.clone()))
    }
}

impl AuditFile {
    fn open(path: &str, fsync: bool) -> std::io::Result<AuditFile> {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(AuditFile {
            writer: BufWriter::with_capacity(8 * 1024, file),
            path: path.to_string(),
            fsync,
            broken: false,
        })
    }

    fn write(&mut self, line: &[u8]) -> std::io::Result<()> {
        self.writer.write_all(line)?;
        self.writer.flush()?;
        if self.fsync {
            self.writer.get_ref().sync_data()?;
        }
        Ok(())
    }
}

impl Sink {
    fn emit(&mut self, level: Level, event: &str, fields: Value) {
        let ts = clock::rfc3339_ms(clock::unix_ms());
        self.buf.clear();

        match self.format {
            LogFormat::Json => {
                let mut map = Map::with_capacity(8);
                map.insert("ts".to_string(), Value::String(ts.clone()));
                map.insert(
                    "level".to_string(),
                    Value::String(level.as_str().to_string()),
                );
                map.insert("event".to_string(), Value::String(event.to_string()));
                if let Value::Object(extra) = fields {
                    for (key, value) in extra {
                        // Reserved keys win over caller fields.
                        map.entry(key).or_insert(value);
                    }
                }
                if serde_json::to_writer(&mut self.buf, &Value::Object(map)).is_err() {
                    return;
                }
            }
            LogFormat::Text => {
                let mut line = format!("{ts} {:<5} {event}", level.as_str().to_uppercase());
                if let Value::Object(extra) = fields {
                    for (key, value) in extra {
                        match value {
                            Value::String(text) => line.push_str(&format!(" {key}={text}")),
                            other => line.push_str(&format!(" {key}={other}")),
                        }
                    }
                }
                self.buf.extend_from_slice(line.as_bytes());
            }
        }
        self.buf.push(b'\n');

        if self.stdout {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            let _ = lock.write_all(&self.buf);
            let _ = lock.flush();
        }
    }
}

/// One line of the routing audit trail. Construct with the helper constructors
/// so the schema stays in one place.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    pub unix_ms: u64,
    pub pid: u32,
    pub version: &'static str,
    pub event: &'static str,
    pub selector: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fails: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quarantine_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_roundtrip_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
}

impl AuditRecord {
    fn base(event: &'static str, selector: &str) -> AuditRecord {
        AuditRecord {
            ts: clock::rfc3339_ms(clock::unix_ms()),
            unix_ms: clock::unix_ms(),
            pid: std::process::id(),
            version: crate::VERSION,
            event,
            selector: selector.to_string(),
            from: None,
            to: None,
            reason: None,
            latency_ms: None,
            fails: None,
            quarantine_ms: None,
            api_ok: None,
            api_roundtrip_ms: None,
            trigger: None,
        }
    }

    pub fn switch(
        selector: &str,
        from: Option<&str>,
        to: &str,
        reason: &str,
        latency_ms: u32,
        fails: u32,
    ) -> AuditRecord {
        let mut record = AuditRecord::base("route_switch", selector);
        record.from = from.map(|s| s.to_string());
        record.to = Some(to.to_string());
        record.reason = Some(reason.to_string());
        record.latency_ms = Some(latency_ms);
        record.fails = Some(fails);
        record
    }

    pub fn switch_result(mut self, ok: bool, roundtrip_ms: u64, trigger: &str) -> AuditRecord {
        self.api_ok = Some(ok);
        self.api_roundtrip_ms = Some(roundtrip_ms);
        self.trigger = Some(trigger.to_string());
        self
    }

    pub fn quarantine(
        selector: &str,
        tag: &str,
        reason: &str,
        quarantine_ms: u64,
        fails: u32,
    ) -> AuditRecord {
        let mut record = AuditRecord::base("quarantine_enter", selector);
        record.to = Some(tag.to_string());
        record.reason = Some(reason.to_string());
        record.quarantine_ms = Some(quarantine_ms);
        record.fails = Some(fails);
        record
    }

    pub fn quarantine_exit(selector: &str, tag: &str) -> AuditRecord {
        let mut record = AuditRecord::base("quarantine_exit", selector);
        record.to = Some(tag.to_string());
        record
    }

    pub fn active_adopted(selector: &str, from: Option<&str>, to: Option<&str>) -> AuditRecord {
        let mut record = AuditRecord::base("active_adopted", selector);
        record.from = from.map(|s| s.to_string());
        record.to = to.map(|s| s.to_string());
        record.reason = Some("external_change".to_string());
        record
    }

    /// First sync after startup: no previous value, so it is not a "change"
    /// made by an operator.
    pub fn initial_active(selector: &str, to: &str) -> AuditRecord {
        let mut record = AuditRecord::base("active_adopted", selector);
        record.to = Some(to.to_string());
        record.reason = Some("initial_sync".to_string());
        record
    }

    pub fn no_healthy(selector: &str, active: Option<&str>) -> AuditRecord {
        let mut record = AuditRecord::base("no_healthy_node", selector);
        record.from = active.map(|s| s.to_string());
        record.reason = Some("all_members_unusable".to_string());
        record
    }

    pub fn intercept_broken(selector: &str, active: Option<&str>, detail: &str) -> AuditRecord {
        let mut record = AuditRecord::base("intercept_failure", selector);
        record.from = active.map(|s| s.to_string());
        record.reason = Some(detail.to_string());
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parsing_and_ordering() {
        assert_eq!(Level::parse("WARN"), Some(Level::Warn));
        assert_eq!(Level::parse("nope"), None);
        assert!(Level::Error < Level::Info);
        assert!(Level::Debug > Level::Info);
    }

    #[test]
    fn audit_record_serializes_expected_keys() {
        let record = AuditRecord::switch(
            "main-outbound",
            Some("node-01"),
            "node-02",
            "active_failed",
            42,
            2,
        )
        .switch_result(true, 3, "probe");
        let line = serde_json::to_value(&record).unwrap();
        assert_eq!(line["event"], "route_switch");
        assert_eq!(line["from"], "node-01");
        assert_eq!(line["to"], "node-02");
        assert_eq!(line["reason"], "active_failed");
        assert_eq!(line["latency_ms"], 42);
        assert_eq!(line["fails"], 2);
        assert_eq!(line["api_ok"], true);
        assert!(line["ts"].as_str().unwrap().ends_with('Z'));
        assert!(line["pid"].as_u64().unwrap() > 0);
    }

    #[test]
    fn audit_file_receives_jsonl() {
        let dir = std::env::temp_dir().join(format!("watchcat-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("routes.jsonl");
        let cfg = LoggingConfig {
            audit_path: Some(path.display().to_string()),
            stdout: false,
            ..LoggingConfig::default()
        };
        let logs = Logs::init(&cfg, Level::Debug).unwrap();
        logs.audit(&AuditRecord::quarantine(
            "main-outbound",
            "node-03",
            "failed",
            300_000,
            2,
        ));
        logs.audit(&AuditRecord::quarantine_exit("main-outbound", "node-03"));

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let parsed: Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("event").is_some());
            assert!(parsed.get("unix_ms").is_some());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_creates_missing_directories() {
        let dir =
            std::env::temp_dir().join(format!("watchcat-audit-nested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("deep").join("routes.jsonl");
        let cfg = LoggingConfig {
            audit_path: Some(path.display().to_string()),
            stdout: false,
            ..LoggingConfig::default()
        };
        let logs = Logs::init(&cfg, Level::Info).unwrap();
        logs.audit(&AuditRecord::no_healthy("main-outbound", Some("node-01")));
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn text_format_is_human_readable() {
        let sink = Sink {
            level: Level::Info,
            format: LogFormat::Text,
            stdout: false,
            audit: None,
            buf: Vec::new(),
        };
        let mut sink = sink;
        sink.emit(
            Level::Info,
            "probe_ok",
            json!({ "tag": "node-01", "ms": 42 }),
        );
        let text = String::from_utf8(sink.buf.clone()).unwrap();
        assert!(text.contains("INFO  probe_ok"));
        assert!(text.contains("tag=node-01"));
    }

    #[test]
    fn disabled_levels_are_dropped() {
        let logs = Logs::for_tests(Level::Warn);
        assert!(!logs.enabled(Level::Info));
        assert!(logs.enabled(Level::Error));
    }
}
