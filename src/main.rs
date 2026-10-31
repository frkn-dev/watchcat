// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! CLI entry point.
//!
//! Modes: run (default), `--check`, `--once`, `--dry-run`, `--set TAG`,
//! `--print-config`, `--nodes`. Everything is single-threaded tokio: the daemon
//! is I/O-latency bound, not CPU bound, so a worker pool would only add memory
//! and context switching.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use watchcat::clash::ClashClient;
use watchcat::clock;
use watchcat::config::Config;
use watchcat::log::{Level, Logs};
use watchcat::notify::Notifier;
use watchcat::supervisor::SupervisorSet;
use watchcat::VERSION;

const HELP: &str = "\
watchcat — sing-box outbound watchdog

USAGE:
    watchcat [OPTIONS]

OPTIONS:
    -c, --config <PATH>     YAML config (default: ./config.yaml, $WATCHCAT_CONFIG)
        --check             Validate configuration and exit
        --print-config      Print the effective configuration (secrets redacted)
        --nodes             Print the effective node pool and exit
        --once              Run a single tick, then exit
        --dry-run           Never send PUT /proxies/… (log the intended switch)
        --force             Ignore the switch cooldown for this run
        --set <TAG>         One-shot: switch the selector to TAG via the Clash API
        --group <TAG>       Only this group (default: every configured group)
        --log-level <LVL>   trace|debug|info|warn|error (overrides config)
    -h, --help              Show this help
    -V, --version           Show version

EXIT CODES:
    0  success            2  Clash API unreachable
    1  configuration/I-O error               3  bad CLI usage
";

struct Args {
    config: Option<PathBuf>,
    check: bool,
    print_config: bool,
    nodes: bool,
    once: bool,
    dry_run: bool,
    force: bool,
    set: Option<String>,
    group: Option<String>,
    log_level: Option<String>,
    help: bool,
    version: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        config: None,
        check: false,
        print_config: false,
        nodes: false,
        once: false,
        dry_run: false,
        force: false,
        set: None,
        group: None,
        log_level: None,
        help: false,
        version: false,
    };
    let mut argv = std::env::args().skip(1);
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                args.config = Some(PathBuf::from(
                    argv.next().ok_or("--config requires a path")?,
                ))
            }
            "--check" => args.check = true,
            "--print-config" => args.print_config = true,
            "--nodes" => args.nodes = true,
            "--once" => args.once = true,
            "--dry-run" => args.dry_run = true,
            "--force" => args.force = true,
            "--set" => args.set = Some(argv.next().ok_or("--set requires a tag")?),
            "--group" => args.group = Some(argv.next().ok_or("--group requires a tag")?),
            "--log-level" => {
                args.log_level = Some(argv.next().ok_or("--log-level requires a value")?)
            }
            "-h" | "--help" => args.help = true,
            "-V" | "--version" => args.version = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(args)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("watchcat: {err}\n\n{HELP}");
            return ExitCode::from(3);
        }
    };
    if args.help {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if args.version {
        println!("watchcat {VERSION}");
        return ExitCode::SUCCESS;
    }

    // Initialise the monotonic clock before anything measures time.
    let _ = clock::mono_ms();

    let config = match Config::load(args.config.as_deref()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("watchcat: {err}");
            return ExitCode::from(1);
        }
    };

    if args.print_config {
        println!("{config:#?}");
        return ExitCode::SUCCESS;
    }

    if args.nodes {
        for group in config.groups() {
            println!("group {}", group.tag);
            let specs = config.node_specs_for(&group);
            if specs.is_empty() {
                println!("  (no explicit node list — the pool comes from the selector at runtime)");
            }
            for spec in specs {
                println!(
                    "  {:<26} protocol={:<14} index={:?} priority={} pinned={}",
                    spec.tag,
                    spec.protocol.as_str(),
                    spec.index,
                    spec.priority,
                    spec.pinned
                );
            }
        }
        return ExitCode::SUCCESS;
    }

    if args.check {
        let groups = config.groups();
        println!("config OK");
        println!("  api:       {}", config.api.base_url);
        println!("  groups:    {}", groups.len());
        for group in &groups {
            let probe = config.probe_for(group);
            let policy = config.policy_for(group);
            println!(
                "    {}: nodes {} ({}), margin {} %, hold {} ticks, adopt {}",
                group.tag,
                config.node_specs_for(group).len(),
                if group.nodes.is_empty() {
                    "pool from selector"
                } else {
                    "explicit"
                },
                policy.switch_margin_pct,
                policy.switch_hold_ticks,
                config.adopt_external(group)
            );
            println!(
                "        probe: {} ms, critical {} every {} ticks, method {:?}, e2e {}",
                probe.interval_ms,
                probe.critical_url.as_deref().unwrap_or("(off)"),
                probe.critical_every_ticks,
                probe.method,
                probe.e2e_enabled
            );
        }
        println!(
            "  probing:   {} ms interval, {} ms fast, {} ms timeout, concurrency {} (shared)",
            config.probe.interval_ms,
            config.probe.fast_interval_ms,
            config.probe.timeout_ms,
            config.probe.concurrency
        );
        println!(
            "  audit:     {}",
            config.logging.audit_path.as_deref().unwrap_or("(disabled)")
        );
        println!(
            "  metrics:   {}",
            if config.metrics.enabled {
                config.metrics.path.as_str()
            } else {
                "(disabled)"
            }
        );
        return ExitCode::SUCCESS;
    }

    if let Some(tag) = args.set.as_deref() {
        return one_shot_set(&config, tag, args.group.as_deref());
    }

    run(config, &args)
}

fn one_shot_set(config: &Config, tag: &str, group: Option<&str>) -> ExitCode {
    let groups = config.groups();
    let selector = match group {
        Some(name) => match groups.iter().find(|g| g.tag == name) {
            Some(found) => found.tag.clone(),
            None => {
                eprintln!("watchcat: group {name:?} is not configured");
                return ExitCode::from(3);
            }
        },
        None if groups.len() == 1 => groups[0].tag.clone(),
        None => {
            eprintln!(
                "watchcat: {} groups configured — pass --group <TAG>",
                groups.len()
            );
            return ExitCode::from(3);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("watchcat: runtime: {err}");
            return ExitCode::from(1);
        }
    };
    runtime.block_on(async {
        let client = match ClashClient::new(&config.api) {
            Ok(client) => client,
            Err(err) => {
                eprintln!("watchcat: {err}");
                return ExitCode::from(1);
            }
        };
        match client.select(&selector, tag).await {
            Ok(result) => {
                println!(
                    "switched {} -> {} (http {}, {} ms)",
                    selector, tag, result.status, result.roundtrip_ms
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("watchcat: switch failed: {err}");
                ExitCode::from(2)
            }
        }
    })
}

fn run(config: Config, args: &Args) -> ExitCode {
    let level = args
        .log_level
        .as_deref()
        .and_then(Level::parse)
        .unwrap_or_else(|| config.log_level());

    let logs = match Logs::init(&config.logging, level) {
        Ok(logs) => logs,
        Err(err) => {
            eprintln!("watchcat: cannot open log sinks: {err}");
            return ExitCode::from(1);
        }
    };

    // Env — не второй конфиг, а аварийный оверрайд. Если он что-то перекрыл,
    // это надо видеть в журнале: иначе ручной прогон без env-файла молча
    // работает не с теми настройками (ровно так A/B получил 401 и «ноль
    // событий», что легко принять за здоровое состояние).
    if !config.env_overrides.is_empty() {
        logs.warn(
            "env_override_applied",
            serde_json::json!({ "keys": config.env_overrides }),
        );
    }

    let delivered = Arc::new(AtomicU64::new(0));
    let telegram_tx = Notifier::spawn(config.telegram.clone(), logs.clone(), delivered.clone())
        .map(|(tx, _handle)| tx);

    // Основной путь оповещений: сигнал в api, решение — там.
    // Telegram напрямую с ноды остаётся как опция (telegram.enabled).
    let report_stats = Arc::new(watchcat::report::ReportStats::default());
    let reporter_tx = watchcat::report::Reporter::spawn(
        config.reporting.clone(),
        logs.clone(),
        report_stats.clone(),
    )
    .map(|(tx, _handle)| tx);

    let notifier = watchcat::notify::EventBus::new(
        [telegram_tx, reporter_tx].into_iter().flatten().collect(),
    );
    if notifier.is_empty() {
        logs.warn(
            "no_notify_sinks",
            serde_json::json!({
                "hint": "telegram.enabled=false и reporting.enabled=false: переключения видны только в audit и метриках",
            }),
        );
    } else {
        logs.info(
            "notify_sinks",
            serde_json::json!({
                "telegram": config.telegram.enabled,
                "api": config.reporting.enabled,
                "node": config.reporting.node,
            }),
        );
    }

    let mut supervisor = match SupervisorSet::new(
        &config,
        logs.clone(),
        notifier,
        args.dry_run,
        args.group.as_deref(),
    ) {
        Ok(supervisor) => supervisor,
        Err(err) => {
            logs.error("init_failed", serde_json::json!({ "error": err }));
            return ExitCode::from(1);
        }
    };

    let groups: Vec<serde_json::Value> = supervisor
        .groups()
        .iter()
        .map(|group| {
            serde_json::json!({
                "tag": group.tag(),
                "configured_nodes": group.configured_nodes(),
            })
        })
        .collect();

    logs.info(
        "start",
        serde_json::json!({
            "version": VERSION,
            "api": config.api.base_url,
            "groups": groups,
            "interval_ms": config.probe.interval_ms,
            "fast_interval_ms": config.probe.fast_interval_ms,
            "probe_timeout_ms": config.probe.timeout_ms,
            "dry_run": args.dry_run,
            "audit_path": config.logging.audit_path,
            "metrics_path": if config.metrics.enabled { Some(&config.metrics.path) } else { None },
            "pid": std::process::id(),
        }),
    );

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            logs.error(
                "runtime_failed",
                serde_json::json!({ "error": err.to_string() }),
            );
            return ExitCode::from(1);
        }
    };

    runtime.block_on(async {
        if args.once {
            let results = supervisor.tick_due(true).await;
            let mut all_ok = true;
            let mut report = Vec::new();
            for (group, stats) in &results {
                all_ok &= stats.api_ok;
                report.push(serde_json::json!({
                    "group": group,
                    "api_ok": stats.api_ok,
                    "probed": stats.probed,
                    "switched": stats.switched,
                    "duration_ms": stats.duration_ms,
                }));
            }
            logs.info("once_complete", serde_json::json!({ "groups": report }));
            return if all_ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }

        let result = supervisor.run(shutdown_signal()).await;
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                logs.error("run_failed", serde_json::json!({ "error": err }));
                ExitCode::from(1)
            }
        }
    })
}

/// Resolves on SIGINT or SIGTERM. Exiting on SIGTERM matters: `systemctl stop`
/// must not wait for the kill timeout.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        let mut interrupt = match signal(SignalKind::interrupt()) {
            Ok(stream) => stream,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = interrupt.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    // Give in-flight audit writes a moment to land.
    tokio::time::sleep(Duration::from_millis(50)).await;
}
