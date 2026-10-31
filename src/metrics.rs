// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! Prometheus textfile metrics.
//!
//! One small file rewritten atomically (`metrics.prom.tmp` → rename) at the end
//! of every tick, so `node_exporter --collector.textfile.directory` picks it up
//! without an HTTP listener and without the daemon owning a port.
//!
//! Cardinality is bounded by the pool size, so per-node series are safe here.
//! Series are emitted with `tag` labels exactly as they appear in the selector,
//! which keeps dashboards joined to sing-box terminology.
//!
//! With several groups every per-group series carries a `group` label, and the
//! bare (unlabelled) names are kept as **totals** — old dashboards and alerts
//! that predate multi-group keep working instead of silently going blank.

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

/// One group as seen by the renderer.
pub struct GroupView<'a> {
    pub tag: &'a str,
    pub router: &'a RouterState,
    pub extra: &'a Extra,
    /// 1 = группа под управлением, 0 = выпала (тег пропал / не selector).
    pub enabled: bool,
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
        groups: &[GroupView],
        totals: &Extra,
        uptime_ms: u64,
    ) -> std::io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        self.render(groups, totals, uptime_ms);

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

    pub fn render(&mut self, groups: &[GroupView], totals: &Extra, uptime_ms: u64) {
        self.buf.clear();

        let _ = writeln!(self.buf, "# HELP watchcat_up 1 if the last tick completed");
        let _ = writeln!(self.buf, "# TYPE watchcat_up gauge");
        let _ = writeln!(self.buf, "watchcat_up {}", u8::from(totals.api_ok));
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
        let _ = writeln!(self.buf, "watchcat_groups {}", groups.len());

        // ---------------------------------------------------------- totals
        // Старые имена без лейбла: сумма по группам. Дашборды, написанные до
        // мульти-группы, продолжают показывать осмысленные числа.
        let _ = writeln!(
            self.buf,
            "watchcat_switches_total {}",
            groups.iter().map(|g| g.router.switches_total()).sum::<u64>()
        );
        let _ = writeln!(
            self.buf,
            "watchcat_last_switch_timestamp_seconds {}",
            totals.last_switch_unix
        );
        let _ = writeln!(
            self.buf,
            "watchcat_loop_duration_ms {}",
            totals.loop_duration_ms
        );
        let _ = writeln!(self.buf, "watchcat_probes_total {}", totals.probes_total);
        let _ = writeln!(
            self.buf,
            "watchcat_api_errors_total {}",
            totals.api_errors_total
        );
        let _ = writeln!(
            self.buf,
            "watchcat_switch_failures_total {}",
            totals.switch_failures_total
        );
        let _ = writeln!(
            self.buf,
            "watchcat_intercept_failures_total {}",
            totals.intercept_failures_total
        );

        // ---------------------------------------------------------- per group
        let _ = writeln!(self.buf, "# TYPE watchcat_group_enabled gauge");
        for group in groups {
            let _ = writeln!(
                self.buf,
                "watchcat_group_enabled{{group=\"{}\"}} {}",
                escape_label(group.tag),
                u8::from(group.enabled)
            );
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_group_switches_total counter");
        for group in groups {
            let _ = writeln!(
                self.buf,
                "watchcat_group_switches_total{{group=\"{}\"}} {}",
                escape_label(group.tag),
                group.router.switches_total()
            );
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_group_active gauge");
        for group in groups {
            let _ = writeln!(
                self.buf,
                "watchcat_group_active{{group=\"{}\",tag=\"{}\"}} 1",
                escape_label(group.tag),
                escape_label(group.router.active().unwrap_or(""))
            );
        }

        let _ = writeln!(
            self.buf,
            "# TYPE watchcat_group_last_switch_timestamp_seconds gauge"
        );
        for group in groups {
            let _ = writeln!(
                self.buf,
                "watchcat_group_last_switch_timestamp_seconds{{group=\"{}\"}} {}",
                escape_label(group.tag),
                group.extra.last_switch_unix
            );
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_group_probes_total counter");
        for group in groups {
            let _ = writeln!(
                self.buf,
                "watchcat_group_probes_total{{group=\"{}\"}} {}",
                escape_label(group.tag),
                group.extra.probes_total
            );
        }

        // `watchcat_active` без лейбла группы сохраняем для старого дашборда,
        // но только когда группа одна — иначе значение неоднозначно.
        if let Some(group) = groups.first().filter(|_| groups.len() == 1) {
            let _ = writeln!(
                self.buf,
                "watchcat_active{{tag=\"{}\"}} 1",
                escape_label(group.router.active().unwrap_or(""))
            );
        }

        // ---------------------------------------------------------- per node
        let _ = writeln!(self.buf, "# TYPE watchcat_node_ewma_ms gauge");
        for group in groups {
            for node in group.router.nodes() {
                let _ = writeln!(
                    self.buf,
                    "watchcat_node_ewma_ms{{group=\"{}\",tag=\"{}\",protocol=\"{}\"}} {}",
                    escape_label(group.tag),
                    escape_label(node.tag()),
                    node.spec.protocol.as_str(),
                    node.ewma_ms()
                );
            }
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_node_fails_total counter");
        for group in groups {
            for node in group.router.nodes() {
                let _ = writeln!(
                    self.buf,
                    "watchcat_node_fails_total{{group=\"{}\",tag=\"{}\"}} {}",
                    escape_label(group.tag),
                    escape_label(node.tag()),
                    node.fails_total
                );
            }
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_node_quarantined gauge");
        for group in groups {
            for node in group.router.nodes() {
                let _ = writeln!(
                    self.buf,
                    "watchcat_node_quarantined{{group=\"{}\",tag=\"{}\"}} {}",
                    escape_label(group.tag),
                    escape_label(node.tag()),
                    u8::from(node.is_quarantined())
                );
            }
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_node_geo_blocked gauge");
        for group in groups {
            for node in group.router.nodes() {
                let _ = writeln!(
                    self.buf,
                    "watchcat_node_geo_blocked{{group=\"{}\",tag=\"{}\"}} {}",
                    escape_label(group.tag),
                    escape_label(node.tag()),
                    u8::from(node.geo_blocked)
                );
            }
        }

        let _ = writeln!(self.buf, "# TYPE watchcat_node_switches_in_total counter");
        for group in groups {
            for node in group.router.nodes() {
                let _ = writeln!(
                    self.buf,
                    "watchcat_node_switches_in_total{{group=\"{}\",tag=\"{}\"}} {}",
                    escape_label(group.tag),
                    escape_label(node.tag()),
                    node.switches_in
                );
            }
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
        let extra = Extra::default();
        let router = router();
        writer.render(
            &[GroupView {
                tag: "fr-exit",
                router: &router,
                extra: &extra,
                enabled: true,
            }],
            &extra,
            12_345,
        );
        let text = writer.snapshot();
        assert!(text.contains("watchcat_up 0"));
        assert!(text.contains("watchcat_active{tag=\"node-01-fr-vless\"} 1"));
        assert!(text.contains("watchcat_group_active{group=\"fr-exit\",tag=\"node-01-fr-vless\"} 1"));
        assert!(text.contains(
            "watchcat_node_ewma_ms{group=\"fr-exit\",tag=\"node-01-fr-vless\",protocol=\"vless\"} 40"
        ));
        assert!(text.contains(
            "watchcat_node_fails_total{group=\"fr-exit\",tag=\"node-02-de-hysteria\"} 1"
        ));
    }

    /// Две группы: счётчики не складываются в одну серию, суммы остаются
    /// в старых именах без лейбла.
    #[test]
    fn two_groups_are_isolated_and_totaled() {
        let mut writer = MetricsWriter::new("/tmp/unused.prom", true);
        let a = router();
        let b = router();
        let mut extra_a = Extra::default();
        extra_a.probes_total = 10;
        let mut extra_b = Extra::default();
        extra_b.probes_total = 4;
        writer.render(
            &[
                GroupView {
                    tag: "fr-exit",
                    router: &a,
                    extra: &extra_a,
                    enabled: true,
                },
                GroupView {
                    tag: "bt-exit",
                    router: &b,
                    extra: &extra_b,
                    enabled: false,
                },
            ],
            &Extra {
                probes_total: 14,
                ..Extra::default()
            },
            1000,
        );
        let text = writer.snapshot();
        assert!(text.contains("watchcat_group_probes_total{group=\"fr-exit\"} 10"));
        assert!(text.contains("watchcat_group_probes_total{group=\"bt-exit\"} 4"));
        assert!(text.contains("watchcat_probes_total 14"));
        assert!(text.contains("watchcat_group_enabled{group=\"bt-exit\"} 0"));
        // двусмысленный `watchcat_active` без группы не выводим
        assert!(!text.contains("watchcat_active{tag="));
    }

    #[test]
    fn writes_atomically() {
        let dir = std::env::temp_dir().join(format!("watchcat-metrics-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("metrics.prom");
        let mut writer = MetricsWriter::new(&path, true);
        let extra = Extra::default();
        let router = router();
        writer
            .write(
                &[GroupView {
                    tag: "fr-exit",
                    router: &router,
                    extra: &extra,
                    enabled: true,
                }],
                &extra,
                1000,
            )
            .unwrap();
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
        let extra = Extra::default();
        let router = router();
        writer
            .write(
                &[GroupView {
                    tag: "fr-exit",
                    router: &router,
                    extra: &extra,
                    enabled: true,
                }],
                &extra,
                1,
            )
            .unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn escapes_quotes_in_labels() {
        assert_eq!(escape_label("a\"b\\c"), "a\\\"b\\\\c");
    }
}
