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
use watchcat::supervisor::Supervisor;
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
        let specs = config.node_specs();
        if specs.is_empty() {
            println!("(no explicit node list — the pool comes from the selector at runtime)");
        }
        for spec in specs {
            println!(
                "{:<28} protocol={:<14} index={:?} priority={} pinned={}",
                spec.tag,
                spec.protocol.as_str(),
                spec.index,
                spec.priority,
                spec.pinned
            );
        }
        return ExitCode::SUCCESS;
    }

    if args.check {
        let policy = config.policy();
        println!("config OK");
        println!("  api:       {}", config.api.base_url);
        println!("  selector:  {}", config.selector.tag);
        println!(
            "  nodes:     {} configured{}",
            config.selector.nodes.len(),
            if config.selector.nodes.is_empty() {
                " (pool read from the selector)"
            } else {
                ""
            }
        );
        println!(
            "  probing:   {} ms interval, {} ms fast, {} ms timeout, concurrency {}",
            config.probe.interval_ms,
            config.probe.fast_interval_ms,
            config.probe.timeout_ms,
            config.probe.concurrency
        );
        println!(
            "  policy:    fail_threshold {}, quarantine {} ms, recovery {} probes, margin {} %",
            policy.fail_threshold,
            policy.quarantine_ms,
            policy.recovery_probes,
            policy.switch_margin_pct
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
        return one_shot_set(&config, tag);
    }

    run(config, &args)
}

fn one_shot_set(config: &Config, tag: &str) -> ExitCode {
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
        match client.select(&config.selector.tag, tag).await {
            Ok(result) => {
                println!(
                    "switched {} -> {} (http {}, {} ms)",
                    config.selector.tag, tag, result.status, result.roundtrip_ms
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

    let delivered = Arc::new(AtomicU64::new(0));
    let notifier = Notifier::spawn(config.telegram.clone(), logs.clone(), delivered.clone())
        .map(|(tx, _handle)| tx);

    let mut supervisor = match Supervisor::new(config.clone(), logs.clone(), notifier, args.dry_run)
    {
        Ok(supervisor) => supervisor,
        Err(err) => {
            logs.error("init_failed", serde_json::json!({ "error": err }));
            return ExitCode::from(1);
        }
    };

    logs.info(
        "start",
        serde_json::json!({
            "version": VERSION,
            "api": config.api.base_url,
            "selector": config.selector.tag,
            "configured_nodes": config.selector.nodes.len(),
            "interval_ms": config.probe.interval_ms,
            "fast_interval_ms": config.probe.fast_interval_ms,
            "probe_timeout_ms": config.probe.timeout_ms,
            "method": format!("{:?}", config.probe.method).to_ascii_lowercase(),
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
            let stats = supervisor.tick(args.force).await;
            logs.info(
                "once_complete",
                serde_json::json!({
                    "api_ok": stats.api_ok,
                    "probed": stats.probed,
                    "switched": stats.switched,
                    "duration_ms": stats.duration_ms,
                }),
            );
            return if stats.api_ok {
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
