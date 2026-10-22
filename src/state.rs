//! Deterministic routing state machine.
//!
//! This module is pure: no I/O, no clocks, no randomness. Every function takes
//! `now` (monotonic milliseconds) as an argument, which makes the whole
//! failover algorithm reproducible in tests to the millisecond and immune to
//! wall-clock jumps.
//!
//! # Model
//!
//! Each member of the selector is a [`NodeState`]. A probe produces an
//! [`Outcome`], which the machine folds into per-node counters:
//!
//! * `consecutive_fails` — hard transport failures/timeouts. Reaching
//!   `fail_threshold` puts the node in quarantine.
//! * `consecutive_blocks` — the exit answered, but the answer was a geo/WAF
//!   block (403/451). Blocks do **not** prove the node is dead, so they are
//!   tracked separately and only affect selection when a better node exists.
//! * `ewma_us` — integer exponential moving average of latency. Integer math
//!   keeps the score bit-identical across platforms (no float rounding).
//! * `quarantined_until` — deadline after which the node is probed for
//!   re-admission; it must pass `recovery_probes` consecutive probes before it
//!   becomes a candidate again.
//!
//! # Selection
//!
//! [`RouterState::decide`] picks the candidate with the lowest
//! `ewma + penalties`, ties broken by `(priority, index, tag)`. It only switches
//! when the candidate is better by `switch_margin_pct`, unless the active node
//! is quarantined, geo-blocked or degraded — that hysteresis is what prevents
//! route flapping between two nodes with near-equal latency.

use crate::parse::Protocol;

/// Outcome of one probe of one node, already classified by the health layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Acceptable answer. `status` is the HTTP status seen (0 for the Clash
    /// delay API, which has no status of its own beyond success).
    Ok { latency_ms: u32, status: u16 },
    /// The exit answered but is blocked for this service (403/451/406).
    Blocked { status: u16, latency_ms: u32 },
    /// Reachable, but the answer is not attributable to the node (5xx, 429,
    /// garbled body). Neither success nor failure.
    Inconclusive { status: u16 },
    /// No answer before the deadline.
    Timeout,
    /// Transport failure: refused, reset, TLS error, malformed reply.
    Transport,
    /// The Clash API itself reported an error for this outbound.
    ApiError(String),
}

impl Outcome {
    pub fn is_hard_failure(&self) -> bool {
        matches!(
            self,
            Outcome::Timeout | Outcome::Transport | Outcome::ApiError(_)
        )
    }

    pub fn latency_ms(&self) -> Option<u32> {
        match self {
            Outcome::Ok { latency_ms, .. } | Outcome::Blocked { latency_ms, .. } => {
                Some(*latency_ms)
            }
            _ => None,
        }
    }

    /// Short stable label for logs and metrics.
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Ok { .. } => "ok",
            Outcome::Blocked { .. } => "blocked",
            Outcome::Inconclusive { .. } => "inconclusive",
            Outcome::Timeout => "timeout",
            Outcome::Transport => "transport",
            Outcome::ApiError(_) => "api_error",
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            Outcome::Ok { status, .. }
            | Outcome::Blocked { status, .. }
            | Outcome::Inconclusive { status } => Some(*status),
            _ => None,
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Outcome::ApiError(message) => Some(message.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineReason {
    /// `fail_threshold` consecutive hard failures.
    Failed,
    /// Repeated geo/WAF blocks on a critical endpoint.
    Blocked,
    /// Operator/CLI forced.
    Manual,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            QuarantineReason::Failed => "failed",
            QuarantineReason::Blocked => "blocked",
            QuarantineReason::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchReason {
    NoActive,
    ActiveMissing,
    ActiveFailed,
    ActiveBlocked,
    ActiveDegraded,
    BetterCandidate,
}

impl SwitchReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SwitchReason::NoActive => "no_active",
            SwitchReason::ActiveMissing => "active_missing",
            SwitchReason::ActiveFailed => "active_failed",
            SwitchReason::ActiveBlocked => "active_blocked",
            SwitchReason::ActiveDegraded => "active_degraded",
            SwitchReason::BetterCandidate => "better_candidate",
        }
    }
}

/// Static per-node configuration coming from `config.yaml` or the tag itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSpec {
    pub tag: String,
    pub protocol: Protocol,
    pub index: Option<u32>,
    /// Lower is better; used as a tie-break and as a hard preference knob.
    pub priority: u32,
    /// Operator pin: this node is preferred whenever it is a candidate.
    pub pinned: bool,
}

impl NodeSpec {
    pub fn from_tag(tag: impl Into<String>) -> NodeSpec {
        let tag = tag.into();
        let parsed = crate::parse::node_tag(&tag)
            .map(|(_, parsed)| parsed)
            .unwrap_or(crate::parse::NodeTag {
                index: None,
                geo: None,
                protocol: Protocol::Other,
            });
        NodeSpec {
            tag,
            protocol: parsed.protocol,
            index: parsed.index,
            priority: 100,
            pinned: false,
        }
    }
}

/// Tuning knobs. Defaults match `docs/DETECTION.md`.
#[derive(Debug, Clone)]
pub struct Policy {
    pub fail_threshold: u32,
    pub quarantine_ms: u64,
    /// `0` disables quarantine on geo-block (block only affects selection).
    pub geo_quarantine_ms: u64,
    /// Absolute EWMA ceiling that counts as "degraded".
    pub degrade_ms: u32,
    /// Relative ceiling, percent of the healthy median (250 = 2.5x).
    pub degrade_factor_pct: u32,
    /// Minimum time between two switches, except when the active node died.
    pub min_switch_interval_ms: u64,
    /// A candidate must be this much faster to displace a healthy active node.
    pub switch_margin_pct: u32,
    /// Consecutive good probes needed to leave quarantine.
    pub recovery_probes: u32,
    /// EWMA weight for the newest sample, per mille (300 = 30 %).
    pub ewma_alpha_permille: u32,
    /// No fresh latency sample within this window ⇒ not a candidate.
    pub stale_ms: u64,
    /// Extra cost per protocol-rank step when picking under blocking pressure.
    pub protocol_penalty_us: u64,
    /// Apply protocol preference penalties only when a block was observed.
    pub prefer_protocol_on_block: bool,
    /// Protocol preference order (best first). Empty ⇒ built-in order.
    pub protocol_preference: Vec<Protocol>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            fail_threshold: 2,
            quarantine_ms: 300_000,
            geo_quarantine_ms: 0,
            degrade_ms: 1_200,
            degrade_factor_pct: 250,
            min_switch_interval_ms: 1_500,
            switch_margin_pct: 20,
            recovery_probes: 2,
            ewma_alpha_permille: 300,
            stale_ms: 60_000,
            protocol_penalty_us: 0,
            prefer_protocol_on_block: true,
            protocol_preference: Vec::new(),
        }
    }
}

impl Policy {
    pub fn validate(&self) -> Result<(), String> {
        if self.fail_threshold == 0 {
            return Err("policy.fail_threshold must be >= 1".into());
        }
        if self.quarantine_ms == 0 {
            return Err("policy.quarantine_ms must be > 0".into());
        }
        if self.recovery_probes == 0 {
            return Err("policy.recovery_probes must be >= 1".into());
        }
        if self.ewma_alpha_permille == 0 || self.ewma_alpha_permille > 1000 {
            return Err("policy.ewma_alpha_permille must be in 1..=1000".into());
        }
        if self.switch_margin_pct >= 100 {
            return Err("policy.switch_margin_pct must be < 100".into());
        }
        if self.stale_ms == 0 {
            return Err("policy.stale_ms must be > 0".into());
        }
        Ok(())
    }

    fn rank(&self, protocol: Protocol) -> u8 {
        if let Some(pos) = self.protocol_preference.iter().position(|p| *p == protocol) {
            return pos.min(u8::MAX as usize) as u8;
        }
        protocol.default_rank()
    }
}

#[derive(Debug, Clone)]
pub struct NodeState {
    pub spec: NodeSpec,
    pub ewma_us: u64,
    pub last_us: u64,
    pub last_sample_at: u64,
    pub last_seen_at: u64,
    pub consecutive_fails: u32,
    pub consecutive_ok: u32,
    pub consecutive_blocks: u32,
    pub quarantined_until: u64,
    pub quarantine_reason: QuarantineReason,
    pub geo_blocked: bool,
    pub geo_blocks_total: u64,
    pub fails_total: u64,
    pub probes_total: u64,
    pub last_outcome: Option<Outcome>,
    /// Counts how many times traffic was switched *to* this node.
    pub switches_in: u32,
}

impl NodeState {
    fn new(spec: NodeSpec) -> NodeState {
        NodeState {
            spec,
            ewma_us: 0,
            last_us: 0,
            last_sample_at: 0,
            last_seen_at: 0,
            consecutive_fails: 0,
            consecutive_ok: 0,
            consecutive_blocks: 0,
            quarantined_until: 0,
            quarantine_reason: QuarantineReason::Failed,
            geo_blocked: false,
            geo_blocks_total: 0,
            fails_total: 0,
            probes_total: 0,
            last_outcome: None,
            switches_in: 0,
        }
    }

    /// Quarantine is sticky: it ends only through explicit re-admission in
    /// [`RouterState::observe`] (or a manual clear), never by the clock alone.
    /// The deadline only says *when* re-admission becomes possible.
    pub fn is_quarantined(&self) -> bool {
        self.quarantined_until != 0
    }

    /// Whether the quarantine window has elapsed and re-admission may happen.
    pub fn quarantine_elapsed(&self, now: u64) -> bool {
        self.quarantined_until != 0 && now >= self.quarantined_until
    }

    pub fn ewma_ms(&self) -> u32 {
        (self.ewma_us / 1000) as u32
    }

    pub fn tag(&self) -> &str {
        &self.spec.tag
    }

    /// Update the EWMA with one sample (integer math, deterministic).
    fn sample(&mut self, latency_ms: u32, now: u64, alpha_permille: u32) {
        let sample_us = (latency_ms as u64).saturating_mul(1000);
        self.ewma_us = if self.ewma_us == 0 {
            sample_us
        } else {
            let alpha = alpha_permille as u64;
            (self.ewma_us * (1000 - alpha) + sample_us * alpha) / 1000
        };
        self.last_us = sample_us;
        self.last_sample_at = now;
    }
}

/// Something worth logging / auditing that happened inside the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    QuarantineEnter {
        tag: String,
        reason: QuarantineReason,
        until_ms: u64,
        fails: u32,
    },
    QuarantineExit {
        tag: String,
    },
    GeoBlocked {
        tag: String,
        status: u16,
        consecutive: u32,
    },
    GeoBlockCleared {
        tag: String,
    },
    Degraded {
        tag: String,
        ewma_ms: u32,
        baseline_ms: u32,
    },
    NoHealthy {
        active: Option<String>,
    },
    MemberAdded {
        tag: String,
    },
    MemberRemoved {
        tag: String,
    },
    ActiveAdopted {
        from: Option<String>,
        to: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    pub from: Option<String>,
    pub to: String,
    pub reason: SwitchReason,
    pub latency_ms: u32,
    pub from_fails: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decision {
    pub switch: Option<Switch>,
    pub events: Vec<Event>,
}

#[derive(Debug, Clone)]
pub struct RouterState {
    policy: Policy,
    nodes: Vec<NodeState>,
    active: Option<String>,
    last_switch_at: u64,
    switches_total: u64,
}

impl RouterState {
    pub fn new(policy: Policy) -> Self {
        RouterState {
            policy,
            nodes: Vec::new(),
            active: None,
            last_switch_at: 0,
            switches_total: 0,
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn nodes(&self) -> &[NodeState] {
        &self.nodes
    }

    pub fn active(&self) -> Option<&str> {
        self.active.as_deref()
    }

    pub fn switches_total(&self) -> u64 {
        self.switches_total
    }

    pub fn last_switch_at(&self) -> u64 {
        self.last_switch_at
    }

    pub fn get(&self, tag: &str) -> Option<&NodeState> {
        self.nodes.iter().find(|node| node.tag() == tag)
    }

    /// Reconcile the configured pool with the selector's member list.
    ///
    /// Order from the Clash API is preserved: it is the tie-break baseline, so
    /// two equal-latency nodes always resolve to the same one.
    pub fn sync_members(&mut self, specs: &[NodeSpec], now: u64) -> Vec<Event> {
        let mut events = Vec::new();

        for spec in specs {
            if !self.nodes.iter().any(|node| node.tag() == spec.tag) {
                events.push(Event::MemberAdded {
                    tag: spec.tag.clone(),
                });
                let mut fresh = NodeState::new(spec.clone());
                fresh.last_seen_at = now;
                self.nodes.push(fresh);
            }
        }

        let keep: Vec<String> = specs.iter().map(|spec| spec.tag.clone()).collect();
        let mut removed = Vec::new();
        self.nodes.retain(|node| {
            let keep_it = keep.iter().any(|tag| tag == node.tag());
            if !keep_it {
                removed.push(node.tag().to_string());
            }
            keep_it
        });
        for tag in removed {
            events.push(Event::MemberRemoved { tag });
        }

        // A stale `active` pointing at a removed member is intentionally left
        // in place: `decide` reports it as `ActiveMissing` and moves traffic,
        // which is more informative than silently forgetting it.
        events
    }

    /// Adopt the active outbound reported by the Clash API. Returns events when
    /// it differs from what the machine believed (external change).
    pub fn adopt_active(&mut self, tag: Option<&str>) -> Vec<Event> {
        let next = tag.map(|t| t.to_string());
        if next == self.active {
            return Vec::new();
        }
        let event = Event::ActiveAdopted {
            from: self.active.clone(),
            to: next.clone().unwrap_or_default(),
        };
        self.active = next;
        vec![event]
    }

    /// Record one probe outcome. Returns events describing state transitions.
    pub fn observe(&mut self, tag: &str, outcome: &Outcome, now: u64) -> Vec<Event> {
        let policy = self.policy.clone();
        let mut events = Vec::new();

        let Some(node) = self.nodes.iter_mut().find(|node| node.tag() == tag) else {
            return events;
        };

        node.probes_total += 1;
        node.last_outcome = Some(outcome.clone());
        node.last_seen_at = now;

        match outcome {
            Outcome::Ok {
                latency_ms,
                status: _,
            } => {
                node.consecutive_fails = 0;
                node.consecutive_ok += 1;
                node.consecutive_blocks = 0;
                node.sample(*latency_ms, now, policy.ewma_alpha_permille);
                if node.geo_blocked {
                    node.geo_blocked = false;
                    events.push(Event::GeoBlockCleared {
                        tag: tag.to_string(),
                    });
                }
                if node.is_quarantined()
                    && node.quarantine_elapsed(now)
                    && node.consecutive_ok >= policy.recovery_probes
                {
                    node.quarantined_until = 0;
                    node.consecutive_fails = 0;
                    events.push(Event::QuarantineExit {
                        tag: tag.to_string(),
                    });
                }
            }
            Outcome::Blocked { status, latency_ms } => {
                node.consecutive_ok = 0;
                node.consecutive_fails = 0;
                node.consecutive_blocks += 1;
                node.geo_blocks_total += 1;
                node.sample(*latency_ms, now, policy.ewma_alpha_permille);
                node.geo_blocked = true;
                events.push(Event::GeoBlocked {
                    tag: tag.to_string(),
                    status: *status,
                    consecutive: node.consecutive_blocks,
                });
                if policy.geo_quarantine_ms > 0
                    && node.consecutive_blocks >= policy.fail_threshold
                    && !node.is_quarantined()
                {
                    node.quarantined_until = now + policy.geo_quarantine_ms;
                    node.quarantine_reason = QuarantineReason::Blocked;
                    events.push(Event::QuarantineEnter {
                        tag: tag.to_string(),
                        reason: QuarantineReason::Blocked,
                        until_ms: node.quarantined_until,
                        fails: node.consecutive_blocks,
                    });
                }
            }
            Outcome::Inconclusive { .. } => {
                // Reachable but not attributable: no counter change, only a
                // freshness update so the node is not pruned as stale.
            }
            Outcome::Timeout | Outcome::Transport | Outcome::ApiError(_) => {
                node.consecutive_ok = 0;
                node.consecutive_fails += 1;
                node.fails_total += 1;
                if node.consecutive_fails >= policy.fail_threshold && !node.is_quarantined() {
                    // Trip the quarantine exactly once per episode. Repeat
                    // failures while already quarantined only increment the
                    // counter: the quarantine is sticky and can end only through
                    // re-admission, so there is nothing to extend and nothing to
                    // re-announce.
                    node.quarantined_until = now + policy.quarantine_ms;
                    node.quarantine_reason = QuarantineReason::Failed;
                    events.push(Event::QuarantineEnter {
                        tag: tag.to_string(),
                        reason: QuarantineReason::Failed,
                        until_ms: node.quarantined_until,
                        fails: node.consecutive_fails,
                    });
                }
            }
        }
        events
    }

    /// Compute the selection decision for `now`.
    ///
    /// `force` skips the switch cooldown (used by the `--once`/manual path).
    pub fn decide(&mut self, now: u64, force: bool) -> Decision {
        let mut decision = Decision::default();

        let active_tag = self.active.clone();
        let active_idx = active_tag
            .as_ref()
            .and_then(|tag| self.nodes.iter().position(|node| node.tag() == tag));

        // 1. No active / active vanished from the pool.
        let active_idx = match active_idx {
            Some(idx) => idx,
            None => {
                if let Some(best) = self.best_candidate(now, None) {
                    let latency = self.nodes[best].ewma_ms();
                    decision.switch = Some(Switch {
                        from: active_tag.clone(),
                        to: self.nodes[best].tag().to_string(),
                        reason: if active_tag.is_some() {
                            SwitchReason::ActiveMissing
                        } else {
                            SwitchReason::NoActive
                        },
                        latency_ms: latency,
                        from_fails: 0,
                    });
                    self.commit_switch(best, now);
                } else {
                    decision
                        .events
                        .push(Event::NoHealthy { active: active_tag });
                }
                return decision;
            }
        };

        let active_quarantined = self.nodes[active_idx].is_quarantined();
        let active_blocked = self.nodes[active_idx].geo_blocked;
        let baseline_ms = self.median_ewma_ms(now);
        let active_ewma = self.nodes[active_idx].ewma_ms();
        let degraded = active_ewma > 0
            && (active_ewma > self.policy.degrade_ms
                || (baseline_ms > 0
                    && (active_ewma as u64) * 100
                        > (baseline_ms as u64) * self.policy.degrade_factor_pct as u64));

        if degraded {
            decision.events.push(Event::Degraded {
                tag: self.nodes[active_idx].tag().to_string(),
                ewma_ms: active_ewma,
                baseline_ms,
            });
        }

        // 2. Active is unusable: switch now, ignoring cooldown and hysteresis.
        let urgent = if active_quarantined {
            Some(SwitchReason::ActiveFailed)
        } else if active_blocked && self.any_unblocked_candidate(now) {
            Some(SwitchReason::ActiveBlocked)
        } else {
            None
        };

        if let Some(reason) = urgent {
            if let Some(best) = self.best_candidate(now, Some(active_idx)) {
                let fails = self.nodes[active_idx].consecutive_fails;
                decision.switch = Some(Switch {
                    from: Some(self.nodes[active_idx].tag().to_string()),
                    to: self.nodes[best].tag().to_string(),
                    reason,
                    latency_ms: self.nodes[best].ewma_ms(),
                    from_fails: fails,
                });
                self.commit_switch(best, now);
                return decision;
            }
            decision.events.push(Event::NoHealthy {
                active: Some(self.nodes[active_idx].tag().to_string()),
            });
            return decision;
        }

        // 3. Healthy active: displace only with a clearly better candidate and
        //    only outside the cooldown window.
        let cooldown_ok =
            force || now.saturating_sub(self.last_switch_at) >= self.policy.min_switch_interval_ms;
        if !cooldown_ok {
            return decision;
        }

        let margin_pct = if degraded {
            0
        } else {
            self.policy.switch_margin_pct
        };
        let active_score = self.score(&self.nodes[active_idx], now, active_blocked || degraded);
        let Some(best) = self.best_candidate(now, Some(active_idx)) else {
            // Nothing better exists. If the active node is itself no longer a
            // candidate (stale/quarantined), this is a real outage: say so
            // instead of silently staying put.
            if !self.is_candidate(&self.nodes[active_idx], now) {
                decision.events.push(Event::NoHealthy {
                    active: Some(self.nodes[active_idx].tag().to_string()),
                });
            }
            return decision;
        };
        let best_score = self.score(&self.nodes[best], now, active_blocked || degraded);
        let threshold = active_score * (100 - margin_pct as u64) / 100;

        if best_score < threshold {
            decision.switch = Some(Switch {
                from: Some(self.nodes[active_idx].tag().to_string()),
                to: self.nodes[best].tag().to_string(),
                reason: if degraded {
                    SwitchReason::ActiveDegraded
                } else {
                    SwitchReason::BetterCandidate
                },
                latency_ms: self.nodes[best].ewma_ms(),
                from_fails: self.nodes[active_idx].consecutive_fails,
            });
            self.commit_switch(best, now);
        }

        decision
    }

    fn commit_switch(&mut self, idx: usize, now: u64) {
        self.active = Some(self.nodes[idx].tag().to_string());
        self.nodes[idx].switches_in = self.nodes[idx].switches_in.saturating_add(1);
        self.last_switch_at = now;
        self.switches_total += 1;
    }

    fn any_unblocked_candidate(&self, now: u64) -> bool {
        self.nodes
            .iter()
            .any(|node| self.is_candidate(node, now) && !node.geo_blocked)
    }

    fn is_candidate(&self, node: &NodeState, now: u64) -> bool {
        node.ewma_us > 0
            && !node.is_quarantined()
            && now.saturating_sub(node.last_sample_at) <= self.policy.stale_ms
    }

    /// Score in microseconds; lower wins. Deterministic integer arithmetic.
    fn score(&self, node: &NodeState, now: u64, block_pressure: bool) -> u64 {
        let _ = now;
        let mut score = node.ewma_us;
        if block_pressure && self.policy.protocol_penalty_us > 0 {
            score += self.policy.rank(node.spec.protocol) as u64 * self.policy.protocol_penalty_us;
        }
        if node.geo_blocked {
            // Keep a blocked-but-alive node selectable, but only as a last
            // resort when nothing better exists (see `best_candidate`).
            score = score.saturating_add(u64::MAX / 4);
        }
        score
    }

    fn best_candidate(&self, now: u64, exclude: Option<usize>) -> Option<usize> {
        let block_pressure = self
            .nodes
            .iter()
            .any(|node| node.geo_blocked && self.is_candidate(node, now));
        let mut best: Option<(usize, u64, u32, u32, &str)> = None;
        for (idx, node) in self.nodes.iter().enumerate() {
            if Some(idx) == exclude || !self.is_candidate(node, now) {
                continue;
            }
            // Under blocking pressure, a blocked node is not a candidate at all.
            if block_pressure && node.geo_blocked {
                continue;
            }
            let score = self.score(node, now, block_pressure);
            let priority = if node.spec.pinned {
                0
            } else {
                node.spec.priority
            };
            let index = node.spec.index.unwrap_or(u32::MAX);
            let key = (idx, score, priority, index, node.tag());
            let better = match best {
                None => true,
                Some((_, best_score, best_priority, best_index, best_tag)) => {
                    (score, priority, index, key.4)
                        < (best_score, best_priority, best_index, best_tag)
                }
            };
            if better {
                best = Some(key);
            }
        }
        best.map(|(idx, ..)| idx)
    }

    /// Median EWMA of healthy nodes — the baseline for relative degradation.
    fn median_ewma_ms(&self, now: u64) -> u32 {
        let mut values: Vec<u32> = self
            .nodes
            .iter()
            .filter(|node| self.is_candidate(node, now))
            .map(|node| node.ewma_ms())
            .collect();
        if values.is_empty() {
            return 0;
        }
        values.sort_unstable();
        values[values.len() / 2]
    }

    /// Mark a node as manually quarantined.
    pub fn quarantine_manual(&mut self, tag: &str, now: u64) -> Option<Event> {
        let policy_quarantine = self.policy.quarantine_ms;
        let node = self.nodes.iter_mut().find(|node| node.tag() == tag)?;
        node.quarantined_until = now + policy_quarantine;
        node.quarantine_reason = QuarantineReason::Manual;
        Some(Event::QuarantineEnter {
            tag: tag.to_string(),
            reason: QuarantineReason::Manual,
            until_ms: node.quarantined_until,
            fails: node.consecutive_fails,
        })
    }

    /// Clear a quarantine (manual recovery).
    pub fn quarantine_clear(&mut self, tag: &str) -> Option<Event> {
        let node = self.nodes.iter_mut().find(|node| node.tag() == tag)?;
        node.quarantined_until = 0;
        node.consecutive_fails = 0;
        Some(Event::QuarantineExit {
            tag: tag.to_string(),
        })
    }

    /// Force the active node (operator request); logs nothing but records the
    /// switch so cooldown/statistics stay honest.
    pub fn force_active(&mut self, tag: &str, now: u64) -> Option<Switch> {
        let idx = self.nodes.iter().position(|node| node.tag() == tag)?;
        let from = self.active.clone();
        if from.as_deref() == Some(tag) {
            return None;
        }
        let latency = self.nodes[idx].ewma_ms();
        self.commit_switch(idx, now);
        Some(Switch {
            from,
            to: tag.to_string(),
            reason: SwitchReason::NoActive,
            latency_ms: latency,
            from_fails: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(n: u32) -> Vec<NodeSpec> {
        (1..=n)
            .map(|i| NodeSpec::from_tag(format!("node-{i:02}-xx-vless")))
            .collect()
    }

    fn ok(latency: u32) -> Outcome {
        Outcome::Ok {
            latency_ms: latency,
            status: 200,
        }
    }

    /// Build a router with `n` nodes, all probed at `latency`, active = node-01.
    fn router(n: u32, latency: u32) -> RouterState {
        let mut router = RouterState::new(Policy::default());
        router.sync_members(&pool(n), 0);
        for i in 1..=n {
            router.observe(&format!("node-{i:02}-xx-vless"), &ok(latency), 100);
        }
        router.adopt_active(Some("node-01-xx-vless"));
        router
    }

    /// Build a router with one exact first sample per node (`latency_ms` are
    /// unsmoothed, since the first sample seeds the EWMA) — active = node-01.
    fn router_latencies(latencies: &[u32]) -> RouterState {
        let mut router = RouterState::new(Policy::default());
        router.sync_members(&pool(latencies.len() as u32), 0);
        for (i, latency) in latencies.iter().enumerate() {
            router.observe(&format!("node-{:02}-xx-vless", i + 1), &ok(*latency), 100);
        }
        router.adopt_active(Some("node-01-xx-vless"));
        router
    }

    #[test]
    fn failure_below_threshold_does_not_switch() {
        let mut router = router(10, 40);
        let events = router.observe("node-01-xx-vless", &Outcome::Timeout, 1000);
        assert!(events.is_empty());
        let decision = router.decide(1000, false);
        assert!(decision.switch.is_none());
        assert_eq!(router.active(), Some("node-01-xx-vless"));
    }

    #[test]
    fn second_failure_quarantines_and_switches() {
        let mut router = router(10, 40);
        router.observe("node-01-xx-vless", &Outcome::Timeout, 1000);
        let events = router.observe("node-01-xx-vless", &Outcome::Transport, 2000);

        let quarantined = events
            .iter()
            .find(|e| matches!(e, Event::QuarantineEnter { .. }))
            .expect("quarantine event");
        match quarantined {
            Event::QuarantineEnter {
                tag,
                reason,
                until_ms,
                fails,
            } => {
                assert_eq!(tag, "node-01-xx-vless");
                assert_eq!(*reason, QuarantineReason::Failed);
                assert_eq!(*until_ms, 2000 + 300_000);
                assert_eq!(*fails, 2);
            }
            _ => unreachable!(),
        }

        let decision = router.decide(2000, false);
        let switch = decision.switch.expect("switch");
        assert_eq!(switch.reason, SwitchReason::ActiveFailed);
        assert_eq!(switch.to, "node-02-xx-vless");
        assert_eq!(router.active(), Some("node-02-xx-vless"));
        assert!(router.get("node-01-xx-vless").unwrap().is_quarantined());
    }

    #[test]
    fn switch_picks_lowest_latency_candidate() {
        let mut router = router(4, 100);
        router.observe("node-03-xx-vless", &ok(30), 200);
        router.observe("node-04-xx-vless", &ok(55), 200);
        router.observe("node-01-xx-vless", &Outcome::Timeout, 300);
        router.observe("node-01-xx-vless", &Outcome::Timeout, 400);
        let decision = router.decide(400, false);
        assert_eq!(decision.switch.unwrap().to, "node-03-xx-vless");
    }

    #[test]
    fn hysteresis_prevents_flapping() {
        // Margin is 20 %: 100 → threshold 80.
        let r = router_latencies(&[100, 85, 100]);
        assert!(r.clone().decide(2000, false).switch.is_none());

        let mut r = router_latencies(&[100, 75, 100]);
        assert!(r.decide(2000, false).switch.is_some());
    }

    #[test]
    fn hysteresis_respects_margin_boundary() {
        let mut r = router_latencies(&[100, 81]);
        assert!(r.decide(2000, false).switch.is_none());
        let mut r = router_latencies(&[100, 79]);
        assert!(r.decide(2000, false).switch.is_some());
    }

    #[test]
    fn cooldown_blocks_rapid_switches() {
        let mut router = router_latencies(&[100, 100, 100]);
        router.observe("node-02-xx-vless", &ok(10), 200);
        assert!(router.decide(2000, false).switch.is_some());
        let after_first = router.active().unwrap().to_string();
        assert_eq!(after_first, "node-02-xx-vless");

        // Immediately make the new active terrible; cooldown must hold.
        router.observe(&after_first, &ok(900), 2100);
        router.observe("node-03-xx-vless", &ok(10), 2100);
        assert!(router.decide(2100, false).switch.is_none());
        // After the cooldown the machine is allowed to move again.
        assert!(router.decide(4000, false).switch.is_some());
    }

    #[test]
    fn forced_decide_ignores_cooldown() {
        let mut router = router_latencies(&[100, 100, 100]);
        router.observe("node-02-xx-vless", &ok(10), 200);
        assert!(router.decide(2000, false).switch.is_some());
        router.observe("node-02-xx-vless", &ok(900), 2100);
        router.observe("node-03-xx-vless", &ok(10), 2100);
        assert!(router.decide(2100, false).switch.is_none());
        assert!(router.decide(2100, true).switch.is_some());
    }

    #[test]
    fn recovery_requires_consecutive_good_probes() {
        let mut router = router(2, 40);
        router.observe("node-01-xx-vless", &Outcome::Timeout, 1000);
        router.observe("node-01-xx-vless", &Outcome::Timeout, 2000);
        assert!(router.get("node-01-xx-vless").unwrap().is_quarantined());

        // Inside the window a success is recorded but does not re-admit.
        router.observe("node-01-xx-vless", &ok(30), 3000);
        assert!(router.get("node-01-xx-vless").unwrap().is_quarantined());

        // Window elapsed, streak 1 < recovery_probes (2): still quarantined.
        router.observe("node-01-xx-vless", &Outcome::Timeout, 302_500);
        router.observe("node-01-xx-vless", &ok(30), 303_000);
        assert!(router.get("node-01-xx-vless").unwrap().is_quarantined());

        // Second consecutive success after the window: re-admitted.
        let events = router.observe("node-01-xx-vless", &ok(30), 304_000);
        assert!(events
            .iter()
            .any(|e| matches!(e, Event::QuarantineExit { .. })));
        assert!(!router.get("node-01-xx-vless").unwrap().is_quarantined());
    }

    #[test]
    fn geo_block_switches_to_unblocked_node() {
        let mut router = router(3, 40);
        router.observe(
            "node-01-xx-vless",
            &Outcome::Blocked {
                status: 403,
                latency_ms: 35,
            },
            1000,
        );
        let decision = router.decide(2000, false);
        let switch = decision.switch.expect("switch away from blocked active");
        assert_eq!(switch.reason, SwitchReason::ActiveBlocked);
        assert_ne!(switch.to, "node-01-xx-vless");
    }

    #[test]
    fn all_nodes_blocked_keeps_active_and_logs() {
        let mut router = router(3, 40);
        for i in 1..=3 {
            router.observe(
                &format!("node-{i:02}-xx-vless"),
                &Outcome::Blocked {
                    status: 403,
                    latency_ms: 40,
                },
                1000,
            );
        }
        let decision = router.decide(2000, false);
        assert!(decision.switch.is_none());
        assert_eq!(router.active(), Some("node-01-xx-vless"));
    }

    #[test]
    fn all_quarantined_does_not_blackhole() {
        let mut router = router(2, 40);
        for tag in ["node-01-xx-vless", "node-02-xx-vless"] {
            router.observe(tag, &Outcome::Timeout, 1000);
            router.observe(tag, &Outcome::Timeout, 2000);
        }
        let decision = router.decide(2000, false);
        assert!(decision.switch.is_none());
        assert!(decision
            .events
            .iter()
            .any(|e| matches!(e, Event::NoHealthy { .. })));
        assert_eq!(router.active(), Some("node-01-xx-vless"));
    }

    #[test]
    fn inconclusive_neither_clears_nor_increments_failures() {
        let mut router = router(2, 40);
        router.observe("node-01-xx-vless", &Outcome::Timeout, 1000);
        router.observe(
            "node-01-xx-vless",
            &Outcome::Inconclusive { status: 502 },
            1001,
        );
        let node = router.get("node-01-xx-vless").unwrap();
        assert_eq!(node.consecutive_fails, 1);
        assert_eq!(node.last_seen_at, 1001);
    }

    #[test]
    fn degraded_active_is_reported_and_replaced() {
        // Active at 1500 ms EWMA (> degrade_ms = 1200), standby at 100 ms.
        let mut router = router_latencies(&[1500, 100]);
        let decision = router.decide(2000, false);
        assert!(decision
            .events
            .iter()
            .any(|e| matches!(e, Event::Degraded { .. })));
        assert_eq!(
            decision.switch.expect("switch").reason,
            SwitchReason::ActiveDegraded
        );
    }

    #[test]
    fn stale_nodes_are_not_candidates() {
        let mut router = RouterState::new(Policy::default());
        router.sync_members(&pool(2), 0);
        router.observe("node-01-xx-vless", &Outcome::Timeout, 1_000_000);
        router.observe("node-02-xx-vless", &ok(10), 1_000_000);
        // node-02 sample is 10 s old at now = 1_010_000, stale_ms = 60 s → still fresh
        assert!(router.decide(1_010_000, true).switch.is_some());
        // At now = 1_200_000 node-02 is stale as well: nothing to switch to.
        let decision = router.decide(1_200_000, true);
        assert!(decision.switch.is_none());
        assert!(decision
            .events
            .iter()
            .any(|e| matches!(e, Event::NoHealthy { .. })));
    }

    #[test]
    fn members_sync_adds_and_removes() {
        let mut router = RouterState::new(Policy::default());
        let events = router.sync_members(&pool(3), 0);
        assert_eq!(events.len(), 3);
        assert_eq!(router.nodes().len(), 3);

        let mut smaller = pool(3);
        smaller.remove(1);
        let events = router.sync_members(&smaller, 10);
        assert!(events
            .iter()
            .any(|e| matches!(e, Event::MemberRemoved { .. })));
        assert_eq!(router.nodes().len(), 2);
        assert!(router.get("node-02-xx-vless").is_none());
    }

    #[test]
    fn active_adopted_from_external_change() {
        let mut router = router(3, 40);
        let events = router.adopt_active(Some("node-03-xx-vless"));
        assert_eq!(
            events,
            vec![Event::ActiveAdopted {
                from: Some("node-01-xx-vless".into()),
                to: "node-03-xx-vless".into()
            }]
        );
        assert_eq!(router.active(), Some("node-03-xx-vless"));
        // Same value again: no event.
        assert!(router.adopt_active(Some("node-03-xx-vless")).is_empty());
    }

    #[test]
    fn pinned_node_wins_tie_break() {
        let mut router = RouterState::new(Policy::default());
        let mut specs = pool(2);
        specs[1].pinned = true;
        router.sync_members(&specs, 0);
        router.observe("node-01-xx-vless", &ok(40), 100);
        router.observe("node-02-xx-vless", &ok(40), 100);
        let decision = router.decide(5000, false);
        assert_eq!(decision.switch.unwrap().to, "node-02-xx-vless");
    }

    #[test]
    fn ewma_is_integer_and_converges() {
        let mut node = NodeState::new(NodeSpec::from_tag("node-01-xx-vless"));
        node.sample(100, 1, 300);
        assert_eq!(node.ewma_us, 100_000);
        node.sample(200, 2, 300);
        // 100_000 * 0.7 + 200_000 * 0.3 = 130_000 exactly
        assert_eq!(node.ewma_us, 130_000);
        for now in 3..200 {
            node.sample(200, now, 300);
        }
        assert!(node.ewma_us <= 200_000);
        assert!(node.ewma_us > 190_000);
    }

    #[test]
    fn protocol_preference_breaks_latency_ties_when_blocked() {
        let policy = Policy {
            protocol_penalty_us: 5_000,
            protocol_preference: vec![Protocol::Hysteria2, Protocol::Vless],
            ..Policy::default()
        };
        let mut router = RouterState::new(policy);
        let specs = vec![
            NodeSpec::from_tag("node-01-xx-vless"),
            NodeSpec::from_tag("node-02-xx-hysteria2"),
        ];
        router.sync_members(&specs, 0);
        // Both blocked? No — one blocked node makes block_pressure true, which
        // makes protocol rank count; equal latency, hysteria2 has rank 0.
        router.observe("node-01-xx-vless", &ok(40), 100);
        router.observe("node-02-xx-hysteria2", &ok(40), 100);
        router.observe(
            "node-01-xx-vless",
            &Outcome::Blocked {
                status: 403,
                latency_ms: 40,
            },
            200,
        );
        let decision = router.decide(5000, false);
        assert_eq!(decision.switch.unwrap().to, "node-02-xx-hysteria2");
    }

    #[test]
    fn policy_validation_rejects_nonsense() {
        let policy = Policy {
            fail_threshold: 0,
            ..Policy::default()
        };
        assert!(policy.validate().is_err());
        let policy = Policy {
            switch_margin_pct: 100,
            ..Policy::default()
        };
        assert!(policy.validate().is_err());
        assert!(Policy::default().validate().is_ok());
    }

    #[test]
    fn quarantine_is_announced_once_per_episode() {
        let mut router = router(2, 40);
        let mut enters = 0;
        for tick in 0..5u64 {
            for event in router.observe("node-01-xx-vless", &Outcome::Timeout, 1000 + tick) {
                if matches!(event, Event::QuarantineEnter { .. }) {
                    enters += 1;
                }
            }
        }
        assert_eq!(
            enters, 1,
            "quarantine must not re-announce on every failure"
        );
        let node = router.get("node-01-xx-vless").unwrap();
        assert_eq!(node.consecutive_fails, 5);
        // The deadline is not extended by later failures: re-admission is gated
        // by the success streak instead. Tripped on the second failure (now=1001).
        assert_eq!(node.quarantined_until, 1001 + 300_000);
    }

    #[test]
    fn manual_quarantine_and_clear() {
        let mut router = router(2, 40);
        assert!(router.quarantine_manual("node-02-xx-vless", 100).is_some());
        assert!(router.get("node-02-xx-vless").unwrap().is_quarantined());
        assert!(router.quarantine_clear("node-02-xx-vless").is_some());
        assert!(!router.get("node-02-xx-vless").unwrap().is_quarantined());
    }
}
