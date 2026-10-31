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
use crate::config::{Config, GroupConfig, ProbeConfig, ProbeMethod};
use crate::health::{ProbeEngine, ProbeReport};
use crate::log::{AuditRecord, Logs};
use crate::metrics::{Extra, GroupView, MetricsWriter};
use crate::notify::{EventBus, NotifyEvent};
use crate::state::{Event, NodeSpec, Outcome, RouterState, Switch};

#[derive(Debug, Default, Clone)]
pub struct TickStats {
    pub api_ok: bool,
    pub probed: usize,
    pub switched: Option<String>,
    pub duration_ms: u64,
}

/// Один супервизор на одну группу выходов.
///
/// Всё состояние (EWMA, карантин, активный член, счётчики) живёт здесь, поэтому
/// группы не могут повлиять друг на друга: переключение в `fr-exit` не трогает
/// `bt-exit`, а ошибка Clash API на одной группе не останавливает остальные.
pub struct GroupSupervisor {
    cfg: Config,
    group: GroupConfig,
    probe_cfg: ProbeConfig,
    adopt: bool,
    clash: Arc<ClashClient>,
    probes: ProbeEngine,
    router: RouterState,
    logs: Logs,
    notifier: EventBus,
    extra: Extra,
    tick_count: u64,
    dry_run: bool,
    api_backoff_ms: u64,
    last_switch_unix: u64,
    start_ms: u64,
    warned_missing: Vec<String>,
    /// Группа отключена: тег пропал из sing-box или это не `selector`.
    /// Тикаем редко, чтобы заметить возврат, но не шуметь.
    disabled: Option<DisabledReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisabledReason {
    Missing,
    NotControllable,
}

impl DisabledReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DisabledReason::Missing => "selector_missing",
            DisabledReason::NotControllable => "selector_not_controllable",
        }
    }
}

impl GroupSupervisor {
    pub fn new(
        cfg: &Config,
        group: GroupConfig,
        logs: Logs,
        notifier: EventBus,
        dry_run: bool,
    ) -> Result<GroupSupervisor, String> {
        let clash = Arc::new(ClashClient::new(&cfg.api)?);
        let probe_cfg = cfg.probe_for(&group);
        let probes = ProbeEngine::new(clash.clone(), &probe_cfg)?;
        let policy = cfg.policy_for(&group);
        Ok(GroupSupervisor {
            router: RouterState::new(policy),
            clash,
            probes,
            logs,
            notifier,
            extra: Extra::default(),
            tick_count: 0,
            dry_run,
            api_backoff_ms: 0,
            last_switch_unix: 0,
            start_ms: clock::mono_ms(),
            warned_missing: Vec::new(),
            disabled: None,
            adopt: cfg.adopt_external(&group),
            probe_cfg,
            group,
            cfg: cfg.clone(),
        })
    }

    pub fn tag(&self) -> &str {
        &self.group.tag
    }

    pub fn router(&self) -> &RouterState {
        &self.router
    }

    pub fn extra(&self) -> &Extra {
        &self.extra
    }

    pub fn uptime_ms(&self) -> u64 {
        clock::mono_ms().saturating_sub(self.start_ms)
    }

    pub fn configured_nodes(&self) -> usize {
        self.cfg.node_specs_for(&self.group).len()
    }

    pub fn disabled_reason(&self) -> Option<DisabledReason> {
        self.disabled
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Probe the critical endpoint on this tick?
    fn critical_due(&self) -> bool {
        if self.probes.critical_url().is_none() {
            return false;
        }
        match self.probe_cfg.critical_every_ticks {
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
        //
        // Три разных исхода, и путать их нельзя: API недоступен (backoff),
        // тег пропал из sing-box (группа в disabled, остальные тикают) и тег
        // есть, но это не selector. Последний случай раньше был тихим отказом:
        // тики шли, `switches_total` замирал, ошибок не было — группа час
        // прожила под `urltest`, а в отчёте выглядела здоровой.
        let selector = match self.clash.selector(&self.group.tag).await {
            Ok(state) => state,
            Err(ClashError::NotFound(_)) => {
                stats = self.mark_disabled(DisabledReason::Missing, stats, started);
                return stats;
            }
            Err(ClashError::NotSelector { ref kind, .. }) => {
                self.extra.api_ok = true;
                self.logs.warn(
                    "selector_not_controllable",
                    json!({
                        "group": self.group.tag,
                        "type": kind,
                        "note": "watchdog manages `selector` only; this group is left alone",
                    }),
                );
                stats = self.mark_disabled(DisabledReason::NotControllable, stats, started);
                return stats;
            }
            Err(err) => {
                self.extra.api_errors_total += 1;
                self.extra.api_ok = false;
                self.api_backoff_ms = (self.api_backoff_ms.max(1_000) * 2).min(30_000);
                self.logs.warn(
                    "clash_api_unavailable",
                    json!({
                        "group": self.group.tag,
                        "error": err.to_string(),
                        "backoff_ms": self.api_backoff_ms,
                    }),
                );
                stats.duration_ms = started.elapsed().as_millis() as u64;
                return stats;
            }
        };
        stats.api_ok = true;
        self.extra.api_ok = true;
        self.api_backoff_ms = 0;

        // Группа вернулась: тег снова на месте и это снова selector.
        if let Some(was) = self.disabled.take() {
            self.logs.info(
                "selector_recovered",
                json!({ "group": self.group.tag, "was": was.as_str() }),
            );
        }

        // 2. Pool reconciliation: config list wins, otherwise trust the API.
        let configured = self.cfg.node_specs_for(&self.group);
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
                            json!({ "tag": spec.tag, "selector": self.group.tag }),
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
                && (self.adopt || self.router.active().is_none())
            {
                let events = self.router.adopt_active(Some(api_active));
                for event in &events {
                    if let Event::ActiveAdopted { from, to } = event {
                        self.logs
                            .info("active_adopted", json!({ "from": from, "to": to }));
                        let record = match from {
                            Some(_) => AuditRecord::active_adopted(
                                &self.group.tag,
                                from.as_deref(),
                                Some(to),
                            ),
                            None => AuditRecord::initial_active(&self.group.tag, to),
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
        if self.probe_cfg.method != ProbeMethod::ClashDelay && self.probes.e2e_enabled() {
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
                        &self.group.tag,
                        Some(&active),
                        report.outcome.label(),
                    ));
                    self.notifier.send(NotifyEvent::InterceptBroken {
                            group: self.group.tag.clone(),
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
                "group": self.group.tag,
                "active": self.router.active(),
                "members": self.router.nodes().len(),
                "probed": stats.probed,
                "critical": include_critical,
                "duration_ms": stats.duration_ms,
                "switches_total": self.router.switches_total(),
            }),
        );
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
            &self.group.tag,
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

        match self.clash.select(&self.group.tag, &switch.to).await {
            Ok(result) => {
                self.last_switch_unix = clock::unix_ms() / 1000;
                self.extra.last_switch_unix = self.last_switch_unix;
                self.logs.info(
                    "route_switch",
                    json!({
                        "selector": self.group.tag,
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
                self.notifier.send(NotifyEvent::Switch {
                        group: self.group.tag.clone(),
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
                        "selector": self.group.tag,
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
                        json!({ "selector": self.group.tag }),
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
                        &self.group.tag,
                        tag,
                        reason.as_str(),
                        quarantine_ms,
                        *fails,
                    ));
                    self.notifier.send(NotifyEvent::Quarantine {
                            group: self.group.tag.clone(),
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
                        .audit(&AuditRecord::quarantine_exit(&self.group.tag, tag));
                    self.notifier.send(NotifyEvent::Recovered {
                            group: self.group.tag.clone(),
                            tag: tag.clone(),
                        },
                    );
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
                        &self.group.tag,
                        active.as_deref(),
                    ));
                    self.notifier.send(NotifyEvent::NoHealthy {
                            group: self.group.tag.clone(),
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

    /// Adaptive period: fast only while the **active** node is unhealthy.
    ///
    /// Standby nodes in quarantine are deliberately not a reason to speed up:
    /// a single dead backup would otherwise pin the daemon at the fast cadence
    /// forever, burning traffic and CPU for no benefit.
    pub fn next_period_ms(&self) -> u64 {
        let active_unhealthy = self
            .router
            .active()
            .and_then(|tag| self.router.get(tag))
            .map(|node| node.is_quarantined() || node.consecutive_fails > 0)
            .unwrap_or(true);
        if active_unhealthy {
            self.probe_cfg.fast_interval_ms
        } else {
            self.probe_cfg.interval_ms
        }
    }

    /// Группа выпала из управления: тег пропал или это не selector.
    ///
    /// Процесс не падает и остальные группы не останавливаются — просто эта
    /// группа перестаёт быть источником событий. Один warn, а не по одному на
    /// тик: иначе за час простоя журнал превращается в шум и настоящие аварии
    /// в нём не видны.
    fn mark_disabled(
        &mut self,
        reason: DisabledReason,
        mut stats: TickStats,
        started: std::time::Instant,
    ) -> TickStats {
        if self.disabled != Some(reason) {
            self.disabled = Some(reason);
            self.logs.warn(
                reason.as_str(),
                json!({
                    "group": self.group.tag,
                    "note": "group disabled; other groups keep ticking",
                }),
            );
        }
        self.extra.api_ok = true;
        stats.duration_ms = started.elapsed().as_millis() as u64;
        stats
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

/// Все группы в одном процессе.
///
/// Тики идут **последовательно**, а не параллельно: на 1 vCPU RU-ноды это
/// единственный способ не превратить 5 групп × concurrency 3 в 15
/// одновременных проб. Побочный плюс — лимит `probe.concurrency` работает как
/// общий, без отдельного семафора.
///
/// У каждой группы свой период: пока `fr-exit` в быстром режиме (активный
/// выход только что упал), `bt-exit` продолжает тикать раз в 5 с и не
/// разгоняется вместе с ней.
pub struct SupervisorSet {
    cfg: Config,
    groups: Vec<GroupSupervisor>,
    /// Абсолютное время (mono_ms), когда группа должна тикнуть в следующий раз.
    due_ms: Vec<u64>,
    metrics: MetricsWriter,
    logs: Logs,
    start_ms: u64,
    metrics_error_logged: bool,
}

impl SupervisorSet {
    pub fn new(
        cfg: &Config,
        logs: Logs,
        notifier: EventBus,
        dry_run: bool,
        only: Option<&str>,
    ) -> Result<SupervisorSet, String> {
        let mut groups = Vec::new();
        for group in cfg.groups() {
            if let Some(only) = only {
                if group.tag != only {
                    continue;
                }
            }
            let supervisor =
                GroupSupervisor::new(cfg, group, logs.clone(), notifier.clone(), dry_run)?;
            groups.push(supervisor);
        }
        if groups.is_empty() {
            return Err(match only {
                Some(tag) => format!("group {tag:?} is not configured"),
                None => "no groups configured".to_string(),
            });
        }
        let due_ms = vec![0; groups.len()];
        Ok(SupervisorSet {
            metrics: MetricsWriter::new(&cfg.metrics.path, cfg.metrics.enabled),
            cfg: cfg.clone(),
            groups,
            due_ms,
            logs,
            start_ms: clock::mono_ms(),
            metrics_error_logged: false,
        })
    }

    pub fn groups(&self) -> &[GroupSupervisor] {
        &self.groups
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Протикнуть те группы, чей период истёк (или все при `force`).
    pub async fn tick_due(&mut self, force: bool) -> Vec<(String, TickStats)> {
        let now = clock::mono_ms();
        let mut out = Vec::new();
        for index in 0..self.groups.len() {
            if !force && now < self.due_ms[index] {
                continue;
            }
            let stats = self.groups[index].tick(force).await;
            self.due_ms[index] = clock::mono_ms() + self.groups[index].next_period_ms();
            out.push((self.groups[index].tag().to_string(), stats));
        }
        self.write_metrics();
        out
    }

    /// Ближайший момент, когда хоть одной группе пора тикать.
    fn next_due_ms(&self) -> u64 {
        self.due_ms.iter().copied().min().unwrap_or(0)
    }

    /// Суммарные счётчики для старых имён метрик без лейбла.
    fn totals(&self) -> Extra {
        let mut totals = Extra::default();
        totals.api_ok = true;
        for group in &self.groups {
            let extra = group.extra();
            totals.probes_total += extra.probes_total;
            totals.api_errors_total += extra.api_errors_total;
            totals.switch_failures_total += extra.switch_failures_total;
            totals.intercept_failures_total += extra.intercept_failures_total;
            totals.last_switch_unix = totals.last_switch_unix.max(extra.last_switch_unix);
            totals.api_ok &= extra.api_ok;
        }
        totals.loop_duration_ms = self
            .groups
            .iter()
            .map(|group| group.extra().loop_duration_ms)
            .max()
            .unwrap_or(0);
        totals
    }

    fn write_metrics(&mut self) {
        let uptime = clock::mono_ms().saturating_sub(self.start_ms);
        let totals = self.totals();
        let views: Vec<GroupView> = self
            .groups
            .iter()
            .map(|group| GroupView {
                tag: group.tag(),
                router: group.router(),
                extra: group.extra(),
                enabled: group.disabled_reason().is_none(),
            })
            .collect();
        if let Err(err) = self.metrics.write(&views, &totals, uptime) {
            if !self.metrics_error_logged {
                self.metrics_error_logged = true;
                self.logs.warn(
                    "metrics_write_failed",
                    json!({ "error": err.to_string(), "path": self.cfg.metrics.path }),
                );
            }
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
        self.tick_due(true).await;
        loop {
            let now = clock::mono_ms();
            let next = self.next_due_ms();
            let wait = next.saturating_sub(now).max(1);
            let sleep = tokio::time::sleep(std::time::Duration::from_millis(wait));
            tokio::pin!(sleep);
            let run_tick = tokio::select! {
                _ = &mut sleep => true,
                _ = &mut shutdown => false,
            };
            if !run_tick {
                self.logs.info(
                    "shutdown",
                    json!({ "groups": self.groups.len() }),
                );
                return Ok(());
            }
            self.tick_due(false).await;
        }
    }
}
