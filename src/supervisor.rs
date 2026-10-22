// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! The supervisor loop: reconcile → probe → decide → apply.
//!
//! One iteration (`tick`) is deliberately linear and boring:
//!
//! 1. read the selector from the Clash API (failures here are *not* node
//!    failures — the loop backs off and changes nothing);
//! 2. reconcile the pool with the selector's member list;
//! 3. adopt an external operator switch, if any;
//! 4. probe every member through the Clash delay API, in bounded parallel;
//! 5. optionally probe the active node end-to-end through the local proxy;
//! 6. feed the state machine, emit events, write the audit trail;
//! 7. apply the switch decision with `PUT /proxies/{selector}`;
//! 8. rewrite the Prometheus textfile.
//!
//! Scheduling is adaptive: the normal interval (`probe.interval_ms`) drops to
//! `probe.fast_interval_ms` while the active node is failing or quarantined, so
//! a dead node is confirmed and replaced quickly, while a healthy pool costs one
//! probe round per interval instead of a busy loop.

use std::sync::Arc;

use serde_json::json;
use tokio::sync::mpsc;

use crate::clash::{ClashClient, ClashError};
use crate::clock;
use crate::config::{Config, ProbeMethod};
use crate::health::{ProbeEngine, ProbeReport};
use crate::log::{AuditRecord, Logs};
use crate::metrics::{Extra, MetricsWriter};
use crate::notify::{send_async, NotifyEvent};
use crate::state::{Event, NodeSpec, Outcome, RouterState, Switch};

#[derive(Debug, Default, Clone)]
pub struct TickStats {
    pub api_ok: bool,
    pub probed: usize,
    pub switched: Option<String>,
    pub duration_ms: u64,
}

pub struct Supervisor {
    cfg: Config,
    clash: Arc<ClashClient>,
    probes: ProbeEngine,
    router: RouterState,
    logs: Logs,
    metrics: MetricsWriter,
    notifier: Option<mpsc::Sender<NotifyEvent>>,
    extra: Extra,
    tick_count: u64,
    dry_run: bool,
    api_backoff_ms: u64,
    last_switch_unix: u64,
    start_ms: u64,
    metrics_error_logged: bool,
    warned_missing: Vec<String>,
}

impl Supervisor {
    pub fn new(
        cfg: Config,
        logs: Logs,
        notifier: Option<mpsc::Sender<NotifyEvent>>,
        dry_run: bool,
    ) -> Result<Supervisor, String> {
        let clash = Arc::new(ClashClient::new(&cfg.api)?);
        let probes = ProbeEngine::new(clash.clone(), &cfg.probe)?;
        let policy = cfg.policy();
        let metrics = MetricsWriter::new(&cfg.metrics.path, cfg.metrics.enabled);
        Ok(Supervisor {
            router: RouterState::new(policy),
            clash,
            probes,
            logs,
            metrics,
            notifier,
            extra: Extra::default(),
            tick_count: 0,
            dry_run,
            api_backoff_ms: 0,
            last_switch_unix: 0,
            start_ms: clock::mono_ms(),
            metrics_error_logged: false,
            warned_missing: Vec::new(),
            cfg,
        })
    }

    pub fn router(&self) -> &RouterState {
        &self.router
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Probe the critical endpoint on this tick?
    fn critical_due(&self) -> bool {
        if self.probes.critical_url().is_none() {
            return false;
        }
        match self.cfg.probe.critical_every_ticks {
            0 => false,
            n => self.tick_count % n as u64 == 0,
        }
    }

    /// Full single iteration. Public so tests and `--once` can drive it.
    pub async fn tick(&mut self, force: bool) -> TickStats {
        let started = std::time::Instant::now();
        let mut stats = TickStats::default();
        self.tick_count += 1;
        let now = clock::mono_ms();

        // 1. Selector state.
        let selector = match self.clash.selector(&self.cfg.selector.tag).await {
            Ok(state) => state,
            Err(err) => {
                self.extra.api_errors_total += 1;
                self.extra.api_ok = false;
                self.api_backoff_ms = (self.api_backoff_ms.max(1_000) * 2).min(30_000);
                self.logs.warn(
                    "clash_api_unavailable",
                    json!({
                        "selector": self.cfg.selector.tag,
                        "error": err.to_string(),
                        "backoff_ms": self.api_backoff_ms,
                    }),
                );
                stats.duration_ms = started.elapsed().as_millis() as u64;
                self.write_metrics(stats.duration_ms);
                return stats;
            }
        };
        stats.api_ok = true;
        self.extra.api_ok = true;
        self.api_backoff_ms = 0;

        // 2. Pool reconciliation: config list wins, otherwise trust the API.
        let configured = self.cfg.node_specs();
        let mut specs: Vec<NodeSpec> = if configured.is_empty() {
            selector
                .all
                .iter()
                .map(|tag| NodeSpec::from_tag(tag.clone()))
                .collect()
        } else {
            configured
                .into_iter()
                .filter(|spec| {
                    let member = selector.all.iter().any(|tag| tag == &spec.tag);
                    if !member && !self.warned_missing.contains(&spec.tag) {
                        self.logs.warn(
                            "configured_node_not_in_selector",
                            json!({ "tag": spec.tag, "selector": self.cfg.selector.tag }),
                        );
                        self.warned_missing.push(spec.tag.clone());
                    }
                    member
                })
                .collect()
        };
        // Keep the API order as the deterministic tie-break baseline.
        specs.sort_by_key(|spec| {
            selector
                .all
                .iter()
                .position(|tag| tag == &spec.tag)
                .unwrap_or(usize::MAX)
        });

        let events = self.router.sync_members(&specs, now);
        self.emit_events(&events);

        // 3. External active-node change (operator via UI or curl).
        if let Some(api_active) = selector.now.as_deref() {
            if self.router.active() != Some(api_active)
                && (self.cfg.selector.adopt_external_changes || self.router.active().is_none())
            {
                let events = self.router.adopt_active(Some(api_active));
                for event in &events {
                    if let Event::ActiveAdopted { from, to } = event {
                        self.logs
                            .info("active_adopted", json!({ "from": from, "to": to }));
                        let record = match from {
                            Some(_) => AuditRecord::active_adopted(
                                &self.cfg.selector.tag,
                                from.as_deref(),
                                Some(to),
                            ),
                            None => AuditRecord::initial_active(&self.cfg.selector.tag, to),
                        };
                        self.logs.audit(&record);
                    }
                }
            } else if self.router.active() != Some(api_active) {
                self.logs.warn(
                    "selector_drift",
                    json!({ "api": api_active, "ours": self.router.active() }),
                );
            }
        }

        // 4. Probe every member.
        let tags: Vec<String> = self
            .router
            .nodes()
            .iter()
            .map(|node| node.tag().to_string())
            .collect();
        let include_critical = self.critical_due();
        let reports = self.probes.probe_members(&tags, include_critical).await;
        stats.probed = reports.len();
        self.extra.probes_total += reports.len() as u64;

        // 5. Fold reports per node and feed the state machine.
        let outcomes = self.fold_reports(&reports, include_critical);
        for (tag, outcome) in &outcomes {
            let events = self.router.observe(tag, outcome, clock::mono_ms());
            self.emit_events(&events);
            self.logs.debug(
                "probe",
                json!({
                    "tag": tag,
                    "outcome": outcome.label(),
                    "latency_ms": outcome.latency_ms(),
                    "status": outcome.status(),
                    "detail": outcome.detail(),
                }),
            );
        }

        // 6. End-to-end proof for the active node (and intercept diagnosis).
        if self.cfg.probe.method != ProbeMethod::ClashDelay && self.probes.e2e_enabled() {
            if let Some(active) = self.router.active().map(|tag| tag.to_string()) {
                let delay_ok = self
                    .router
                    .get(&active)
                    .and_then(|node| node.last_outcome.clone())
                    .map(|outcome| !outcome.is_hard_failure())
                    .unwrap_or(false);
                let url = self.probes.base_url().clone();
                let report = self.probes.probe_e2e(&active, &url).await;
                self.extra.probes_total += 1;

                if report.outcome.is_hard_failure() && delay_ok {
                    self.extra.intercept_failures_total += 1;
                    self.logs.error(
                        "intercept_probe_failed",
                        json!({
                            "tag": active,
                            "outcome": report.outcome.label(),
                            "target": report.url,
                            "hint": "Clash delay succeeded but the local proxy path failed: \
                                     the inbounds/intercept, not the node, is broken",
                        }),
                    );
                    self.logs.audit(&AuditRecord::intercept_broken(
                        &self.cfg.selector.tag,
                        Some(&active),
                        report.outcome.label(),
                    ));
                    send_async(
                        &self.notifier,
                        NotifyEvent::InterceptBroken {
                            detail: format!(
                                "{} via {}: {}",
                                active,
                                report.url,
                                report.outcome.label()
                            ),
                        },
                    );
                } else {
                    self.logs.debug(
                        "intercept_probe_ok",
                        json!({
                            "tag": active,
                            "latency_ms": report.outcome.latency_ms(),
                            "status": report.outcome.status(),
                            "exit_ip": report.trace.as_ref().and_then(|t| t.ip.clone()),
                            "exit_loc": report.trace.as_ref().and_then(|t| t.loc.clone()),
                        }),
                    );
                }
            }
        }

        // 7. Decide and apply.
        let decision = self.router.decide(clock::mono_ms(), force);
        self.emit_events(&decision.events);
        if let Some(switch) = decision.switch {
            stats.switched = Some(switch.to.clone());
            self.apply_switch(&switch).await;
        }

        // 8. Metrics and a per-tick summary line.
        stats.duration_ms = started.elapsed().as_millis() as u64;
        self.logs.info(
            "tick",
            json!({
                "active": self.router.active(),
                "members": self.router.nodes().len(),
                "probed": stats.probed,
                "critical": include_critical,
                "duration_ms": stats.duration_ms,
                "switches_total": self.router.switches_total(),
            }),
        );
        self.write_metrics(stats.duration_ms);
        stats
    }

    /// Combine base + critical reports into one outcome per node.
    ///
    /// Liveness comes from the cheap base probe; blocking comes from the
    /// critical one. A hard failure on either is a hard failure of the node.
    fn fold_reports(
        &self,
        reports: &[ProbeReport],
        include_critical: bool,
    ) -> Vec<(String, Outcome)> {
        let mut base: Vec<(&str, &ProbeReport)> = Vec::new();
        let mut critical: Vec<(&str, &ProbeReport)> = Vec::new();
        for report in reports {
            if report.critical {
                critical.push((report.tag.as_str(), report));
            } else {
                base.push((report.tag.as_str(), report));
            }
        }

        let mut out = Vec::with_capacity(base.len());
        for (tag, base_report) in base {
            let base_outcome = base_report.outcome.clone();
            let critical_outcome = if include_critical {
                critical
                    .iter()
                    .find(|(critical_tag, _)| *critical_tag == tag)
                    .map(|(_, report)| report.outcome.clone())
            } else {
                None
            };

            let combined = match critical_outcome {
                Some(critical) => {
                    if base_outcome.is_hard_failure() {
                        base_outcome
                    } else if critical.is_hard_failure() {
                        critical
                    } else if let Outcome::Blocked { status, .. } = critical {
                        Outcome::Blocked {
                            status,
                            latency_ms: base_outcome.latency_ms().unwrap_or(0),
                        }
                    } else {
                        base_outcome
                    }
                }
                None => base_outcome,
            };
            out.push((tag.to_string(), combined));
        }
        out
    }

    async fn apply_switch(&mut self, switch: &Switch) {
        let reason = switch.reason.as_str();
        let record = AuditRecord::switch(
            &self.cfg.selector.tag,
            switch.from.as_deref(),
            &switch.to,
            reason,
            switch.latency_ms,
            switch.from_fails,
        );

        if self.dry_run {
            self.logs.info(
                "switch_dry_run",
                json!({
                    "from": switch.from,
                    "to": switch.to,
                    "reason": reason,
                    "latency_ms": switch.latency_ms,
                }),
            );
            self.logs.audit(&record.switch_result(true, 0, "dry_run"));
            return;
        }

        match self.clash.select(&self.cfg.selector.tag, &switch.to).await {
            Ok(result) => {
                self.last_switch_unix = clock::unix_ms() / 1000;
                self.extra.last_switch_unix = self.last_switch_unix;
                self.logs.info(
                    "route_switch",
                    json!({
                        "selector": self.cfg.selector.tag,
                        "from": switch.from,
                        "to": switch.to,
                        "reason": reason,
                        "latency_ms": switch.latency_ms,
                        "fails": switch.from_fails,
                        "api_roundtrip_ms": result.roundtrip_ms,
                    }),
                );
                self.logs
                    .audit(&record.switch_result(true, result.roundtrip_ms, "probe"));
                send_async(
                    &self.notifier,
                    NotifyEvent::Switch {
                        from: switch.from.clone(),
                        to: switch.to.clone(),
                        reason: reason.to_string(),
                        latency_ms: switch.latency_ms,
                        api_roundtrip_ms: Some(result.roundtrip_ms),
                    },
                );
            }
            Err(err) => {
                self.extra.switch_failures_total += 1;
                self.logs.error(
                    "route_switch_failed",
                    json!({
                        "selector": self.cfg.selector.tag,
                        "to": switch.to,
                        "error": err.to_string(),
                        "note": "state re-syncs from the API on the next tick",
                    }),
                );
                self.logs.audit(&record.switch_result(false, 0, "probe"));
                // Deliberately no local rollback: the next tick reads `now`
                // from the API and re-adopts the truth.
                if matches!(err, ClashError::NotFound(_)) {
                    self.logs.error(
                        "selector_missing",
                        json!({ "selector": self.cfg.selector.tag }),
                    );
                }
            }
        }
    }

    fn emit_events(&mut self, events: &[Event]) {
        for event in events {
            match event {
                Event::QuarantineEnter {
                    tag,
                    reason,
                    until_ms,
                    fails,
                } => {
                    let quarantine_ms = until_ms.saturating_sub(clock::mono_ms());
                    self.logs.warn(
                        "quarantine_enter",
                        json!({
                            "tag": tag,
                            "reason": reason.as_str(),
                            "fails": fails,
                            "quarantine_ms": quarantine_ms,
                        }),
                    );
                    self.logs.audit(&AuditRecord::quarantine(
                        &self.cfg.selector.tag,
                        tag,
                        reason.as_str(),
                        quarantine_ms,
                        *fails,
                    ));
                    send_async(
                        &self.notifier,
                        NotifyEvent::Quarantine {
                            tag: tag.clone(),
                            reason: reason.as_str().to_string(),
                            quarantine_ms,
                            fails: *fails,
                        },
                    );
                }
                Event::QuarantineExit { tag } => {
                    self.logs.info("quarantine_exit", json!({ "tag": tag }));
                    self.logs
                        .audit(&AuditRecord::quarantine_exit(&self.cfg.selector.tag, tag));
                    send_async(&self.notifier, NotifyEvent::Recovered { tag: tag.clone() });
                }
                Event::GeoBlocked {
                    tag,
                    status,
                    consecutive,
                } => {
                    self.logs.warn(
                        "geo_blocked",
                        json!({ "tag": tag, "status": status, "consecutive": consecutive }),
                    );
                }
                Event::GeoBlockCleared { tag } => {
                    self.logs.info("geo_block_cleared", json!({ "tag": tag }));
                }
                Event::Degraded {
                    tag,
                    ewma_ms,
                    baseline_ms,
                } => {
                    self.logs.warn(
                        "degraded",
                        json!({ "tag": tag, "ewma_ms": ewma_ms, "baseline_ms": baseline_ms }),
                    );
                }
                Event::NoHealthy { active } => {
                    self.logs.error(
                        "no_healthy_node",
                        json!({
                            "active": active,
                            "note": "keeping the current outbound; not blackholing traffic",
                        }),
                    );
                    self.logs.audit(&AuditRecord::no_healthy(
                        &self.cfg.selector.tag,
                        active.as_deref(),
                    ));
                    send_async(
                        &self.notifier,
                        NotifyEvent::NoHealthy {
                            active: active.clone(),
                        },
                    );
                }
                Event::MemberAdded { tag } => {
                    self.logs.info("member_added", json!({ "tag": tag }));
                }
                Event::MemberRemoved { tag } => {
                    self.logs.info("member_removed", json!({ "tag": tag }));
                }
                Event::ActiveAdopted { .. } => {}
            }
        }
    }

    fn write_metrics(&mut self, loop_duration_ms: u64) {
        self.extra.loop_duration_ms = loop_duration_ms;
        self.extra.last_switch_unix = self.last_switch_unix;
        let uptime = clock::mono_ms().saturating_sub(self.start_ms);
        if let Err(err) = self.metrics.write(&self.router, &self.extra, uptime) {
            if !self.metrics_error_logged {
                self.metrics_error_logged = true;
                self.logs.warn(
                    "metrics_write_failed",
                    json!({ "error": err.to_string(), "path": self.cfg.metrics.path }),
                );
            }
        }
    }

    /// Adaptive period: fast only while the **active** node is unhealthy.
    ///
    /// Standby nodes in quarantine are deliberately not a reason to speed up:
    /// a single dead backup would otherwise pin the daemon at the fast cadence
    /// forever, burning traffic and CPU for no benefit.
    fn next_period_ms(&self) -> u64 {
        let active_unhealthy = self
            .router
            .active()
            .and_then(|tag| self.router.get(tag))
            .map(|node| node.is_quarantined() || node.consecutive_fails > 0)
            .unwrap_or(true);
        if active_unhealthy {
            self.cfg.probe.fast_interval_ms
        } else {
            self.cfg.probe.interval_ms
        }
    }

    /// Run until `shutdown` resolves.
    pub async fn run<F>(&mut self, shutdown: F) -> Result<(), String>
    where
        F: std::future::Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        // Prime immediately: state, audit and metrics should exist without
        // waiting a whole period after startup.
        self.tick(false).await;
        loop {
            let period = self.next_period_ms();
            let sleep = tokio::time::sleep(std::time::Duration::from_millis(period));
            tokio::pin!(sleep);
            let run_tick = tokio::select! {
                _ = &mut sleep => true,
                _ = &mut shutdown => false,
            };
            if !run_tick {
                self.logs
                    .info("shutdown", json!({ "ticks": self.tick_count }));
                return Ok(());
            }
            self.tick(false).await;
        }
    }
}
