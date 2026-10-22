//! Watchcat — a sing-box outbound watchdog.
//!
//! The supervisor asks the sing-box Clash API for the current selector state,
//! probes every member outbound, feeds the results into a pure deterministic
//! state machine ([`state`]), and applies the decisions back through the Clash
//! API (`PUT /proxies/{selector}`). Parsing is nom-based ([`parse`]), all I/O is
//! tokio on a single-threaded runtime, and every routing decision lands in a
//! dedicated audit log ([`log`]).

pub mod clash;
pub mod clock;
pub mod config;
pub mod health;
pub mod log;
pub mod metrics;
pub mod net;
pub mod notify;
pub mod parse;
pub mod state;
pub mod supervisor;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
