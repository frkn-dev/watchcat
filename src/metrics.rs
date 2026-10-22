//! Prometheus textfile metrics.
//!
//! One small file rewritten atomically (`metrics.prom.tmp` → rename) at the end
//! of every tick, so `node_exporter --collector.textfile.directory` picks it up
//! without an HTTP listener and without the daemon owning a port.
//!
//! Cardinality is bounded by the pool size (10 nodes), so per-node series are
//! safe here. Series are emitted with `tag` labels exactly as they appear in the
//! selector, which keeps dashboards joined to sing-box terminology.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::state::RouterState;

#[derive(Debug, Default, Clone)]
pub struct Extra {
    /// Duration of the last full tick.
    pub loop_duration_ms: u64,
    /// Probes performed since start.
    pub probes_total: u64,
    /// Clash API requests that failed since start.
    pub api_errors_total: u64,
    /// Switches rejected by the API (sing-box said no).
    pub switch_failures_total: u64,
    /// End-to-end probe failures that were traced to the local intercept.
    pub intercept_failures_total: u64,
    /// Whether the last tick could reach the Clash API.
    pub api_ok: bool,
    /// Unix seconds of the last successful switch (0 = never).
    pub last_switch_unix: u64,
}

pub struct MetricsWriter {
    path: PathBuf,
    enabled: bool,
    buf: String,
}

impl MetricsWriter {
    pub fn new(path: impl AsRef<Path>, enabled: bool) -> MetricsWriter {
        MetricsWriter {
            path: path.as_ref().to_path_buf(),
            enabled,
            buf: String::with_capacity(8 * 1024),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Rewrite the textfile. Errors are reported to the caller, which logs them
    /// once per failure without stopping the loop.
    pub fn write(
        &mut self,
        router: &RouterState,
        extra: &Extra,
        uptime_ms: u64,
    ) -> std::io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        self.render(router, extra, uptime_ms);

        let tmp = self.path.with_extension("prom.tmp");
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(self.buf.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_data()?;
        }
        std::fs::rename(&tmp, &self.path)
    }

    pub fn render(&mut self, router: &RouterState, extra: &Extra, uptime_ms: u64) {
        self.buf.clear();
        let active = router.active().unwrap_or("");

        let _ = writeln!(self.buf, "# HELP watchcat_up 1 if the last tick completed");
        let _ = writeln!(self.buf, "# TYPE watchcat_up gauge");
        let _ = writeln!(self.buf, "watchcat_up {}", u8::from(extra.api_ok));
        let _ = writeln!(
            self.buf,
            "watchcat_build_info{{version=\"{}\"}} 1",
            crate::VERSION
        );
        let _ = writeln!(
            self.buf,
            "watchcat_uptime_seconds {:.3}",
            uptime_ms as f64 / 1000.0
        );
        let _ = writeln!(
            self.buf,
            "watchcat_active{{tag=\"{}\"}} 1",
            escape_label(active)
        );
        let _ = writeln!(
            self.buf,
            "watchcat_switches_total {}",
            router.switches_total()
        );
        let _ = writeln!(
            self.buf,
            "watchcat_last_switch_timestamp_seconds {}",
            extra.last_switch_unix
        );
        let _ = writeln!(
            self.buf,
            "watchcat_loop_duration_ms {}",
            extra.loop_duration_ms
        );
        let _ = writeln!(self.buf, "watchcat_probes_total {}", extra.probes_total);
        let _ = writeln!(
            self.buf,
            "watchcat_api_errors_total {}",
            extra.api_errors_total
        );
        let _ = writeln!(
            self.buf,
            "watchcat_switch_failures_total {}",
            extra.switch_failures_total
        );
        let _ = writeln!(
            self.buf,
            "watchcat_intercept_failures_total {}",
            extra.intercept_failures_total
        );

        let _ = writeln!(self.buf, "# TYPE watchcat_node_ewma_ms gauge");
        for node in router.nodes() {
            let _ = writeln!(
                self.buf,
                "watchcat_node_ewma_ms{{tag=\"{}\",protocol=\"{}\"}} {}",
                escape_label(node.tag()),
                node.spec.protocol.as_str(),
                node.ewma_ms()
            );
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_node_fails_total counter");
        for node in router.nodes() {
            let _ = writeln!(
                self.buf,
                "watchcat_node_fails_total{{tag=\"{}\"}} {}",
                escape_label(node.tag()),
                node.fails_total
            );
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_node_quarantined gauge");
        for node in router.nodes() {
            let _ = writeln!(
                self.buf,
                "watchcat_node_quarantined{{tag=\"{}\"}} {}",
                escape_label(node.tag()),
                u8::from(node.is_quarantined())
            );
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_node_geo_blocked gauge");
        for node in router.nodes() {
            let _ = writeln!(
                self.buf,
                "watchcat_node_geo_blocked{{tag=\"{}\"}} {}",
                escape_label(node.tag()),
                u8::from(node.geo_blocked)
            );
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_node_switches_in_total counter");
        for node in router.nodes() {
            let _ = writeln!(
                self.buf,
                "watchcat_node_switches_in_total{{tag=\"{}\"}} {}",
                escape_label(node.tag()),
                node.switches_in
            );
        }
    }

    pub fn snapshot(&self) -> &str {
        &self.buf
    }
}

/// Escape a Prometheus label value per the exposition format spec.
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{NodeSpec, Outcome, Policy};

    fn router() -> RouterState {
        let mut router = RouterState::new(Policy::default());
        router.sync_members(
            &[
                NodeSpec::from_tag("node-01-fr-vless"),
                NodeSpec::from_tag("node-02-de-hysteria"),
            ],
            0,
        );
        router.observe(
            "node-01-fr-vless",
            &Outcome::Ok {
                latency_ms: 40,
                status: 200,
            },
            10,
        );
        router.observe("node-02-de-hysteria", &Outcome::Timeout, 10);
        router.adopt_active(Some("node-01-fr-vless"));
        router
    }

    #[test]
    fn renders_expected_series() {
        let mut writer = MetricsWriter::new("/tmp/unused.prom", true);
        writer.render(&router(), &Extra::default(), 12_345);
        let text = writer.snapshot();
        assert!(text.contains("watchcat_up 0"));
        assert!(text.contains("watchcat_active{tag=\"node-01-fr-vless\"} 1"));
        assert!(
            text.contains("watchcat_node_ewma_ms{tag=\"node-01-fr-vless\",protocol=\"vless\"} 40")
        );
        assert!(text.contains(
            "watchcat_node_ewma_ms{tag=\"node-02-de-hysteria\",protocol=\"hysteria2\"} 0"
        ));
        assert!(text.contains("watchcat_node_fails_total{tag=\"node-02-de-hysteria\"} 1"));
        assert!(text.contains("watchcat_node_quarantined{tag=\"node-02-de-hysteria\"} 0"));
    }

    #[test]
    fn writes_atomically() {
        let dir = std::env::temp_dir().join(format!("watchcat-metrics-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("metrics.prom");
        let mut writer = MetricsWriter::new(&path, true);
        writer.write(&router(), &Extra::default(), 1000).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("watchcat_switches_total"));
        assert!(!path.with_extension("prom.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_writer_touches_nothing() {
        let path = std::env::temp_dir().join("watchcat-disabled.prom");
        let _ = std::fs::remove_file(&path);
        let mut writer = MetricsWriter::new(&path, false);
        writer.write(&router(), &Extra::default(), 1).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn escapes_quotes_in_labels() {
        assert_eq!(escape_label("a\"b\\c"), "a\\\"b\\\\c");
    }
}
