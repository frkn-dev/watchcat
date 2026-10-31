// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 FRKN
//! Configuration: YAML file, `.env` file, environment variables, CLI path.
//!
//! Precedence (highest wins):
//!
//! 1. environment variables (`WATCHCAT_*`) or the `.env` file they are read from
//! 2. the YAML file (`--config`, `$WATCHCAT_CONFIG`, `./config.yaml`)
//! 3. built-in defaults
//!
//! `deny_unknown_fields` is deliberate: a typo like `quarantine_secs:` instead
//! of `quarantine_ms:` would otherwise silently fall back to the default and
//! leave a failover guard with the wrong timeout. Configuration errors are
//! fatal at startup (`--check` reports them without touching anything).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::parse::{self, Protocol, Url};
use crate::state::{NodeSpec, Policy};

#[derive(Debug)]
pub enum ConfigError {
    Io(String, std::io::Error),
    Yaml(String),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(path, err) => write!(f, "cannot read {path}: {err}"),
            ConfigError::Yaml(err) => write!(f, "invalid YAML: {err}"),
            ConfigError::Invalid(err) => write!(f, "invalid config: {err}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub api: ApiConfig,
    /// Одна группа (старый формат). `None` — если задан `selectors`.
    pub selector: Option<SelectorConfig>,
    /// Несколько групп выходов в одном процессе.
    pub selectors: Vec<GroupConfig>,
    pub probe: ProbeConfig,
    pub policy: PolicyConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub telegram: TelegramConfig,
    /// Отправка событий в api (основной путь оповещений).
    #[serde(default)]
    pub reporting: ReportingConfig,
    /// Ключи, которые пришли из env и перекрыли YAML. Пусто на боевой ноде —
    /// значит единственный источник правды конфиг-файл. Не сериализуется:
    /// это диагностика, а не настройка.
    #[serde(skip)]
    pub env_overrides: Vec<String>,
    /// Env-ключи, которые в текущем режиме не имеют смысла и поэтому
    /// проигнорированы (например `WATCHCAT_SELECTOR` при `selectors:`).
    #[serde(skip)]
    pub env_ignored: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    pub base_url: String,
    pub secret: Option<String>,
    pub connect_timeout_ms: u64,
    pub timeout_ms: u64,
}

impl fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiConfig")
            .field("base_url", &self.base_url)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        ApiConfig {
            base_url: "http://127.0.0.1:9090".to_string(),
            secret: None,
            connect_timeout_ms: 500,
            timeout_ms: 1_500,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SelectorConfig {
    pub tag: String,
    /// Explicit pool. Empty ⇒ take the selector's member list from the API.
    pub nodes: Vec<NodeConfig>,
    /// Adopt a selector change made by an operator instead of fighting it.
    pub adopt_external_changes: bool,
}

/// Одна группа выходов внутри `selectors:`.
///
/// `probe` и `policy` — оверрайды глобальных секций, применяются по ключу
/// целиком (никакого частичного мержа вложенных объектов): иначе нельзя
/// понять, что именно в итоге действует.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GroupConfig {
    pub tag: String,
    /// Явный пул. Пусто ⇒ состав берётся из поля `all` группы в Clash API.
    pub nodes: Vec<NodeConfig>,
    /// Подхватывать чужое переключение. `None` ⇒ глобальное значение.
    pub adopt_external_changes: Option<bool>,
    pub probe: Option<ProbeOverrides>,
    pub policy: Option<PolicyConfig>,
}

impl From<SelectorConfig> for GroupConfig {
    fn from(selector: SelectorConfig) -> GroupConfig {
        GroupConfig {
            tag: selector.tag,
            nodes: selector.nodes,
            adopt_external_changes: Some(selector.adopt_external_changes),
            probe: None,
            policy: None,
        }
    }
}

/// Per-group overrides of `probe:`. Only the fields that genuinely differ
/// between groups live here — a RU-exit cannot be measured with the same URL as
/// a FR-exit, and `bt-exit` does not proxy HTTPS at all.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProbeOverrides {
    pub base_url: Option<String>,
    pub critical_url: Option<String>,
    pub e2e_proxy: Option<String>,
    pub e2e_enabled: Option<bool>,
    pub critical_every_ticks: Option<u32>,
    pub method: Option<ProbeMethod>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub tag: String,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub pinned: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMethod {
    /// Only the Clash delay endpoint: sing-box dials, we just ask.
    ClashDelay,
    /// Only the local proxy inbound (SOCKS5 + TLS + HTTP).
    EndToEnd,
    /// Both: Clash delay for every member, end-to-end for the active node.
    Both,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProbeConfig {
    pub interval_ms: u64,
    /// Interval used after a failure until the pool looks healthy again.
    pub fast_interval_ms: u64,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub method: ProbeMethod,
    /// Cheap connectivity probe used for latency scoring.
    pub base_url: String,
    /// Blocking-sensitive endpoint (geo/WAF checks).
    pub critical_url: Option<String>,
    /// Probe the critical URL every N ticks per node (0 disables).
    pub critical_every_ticks: u32,
    /// Statuses that mean "reachable and acceptable".
    pub accept_status: Vec<u16>,
    /// Statuses that mean "exit is blocked for this service".
    pub block_status: Vec<u16>,
    /// End-to-end probe through the local proxy inbound.
    pub e2e_proxy: String,
    pub e2e_enabled: bool,
    /// Treat an end-to-end failure while the Clash delay succeeds as a local
    /// intercept breakage (reported, never "fixed" by switching nodes).
    pub e2e_detect_intercept: bool,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            interval_ms: 5_000,
            fast_interval_ms: 1_000,
            timeout_ms: 2_000,
            concurrency: 10,
            method: ProbeMethod::Both,
            base_url: "https://1.1.1.1/cdn-cgi/trace".to_string(),
            critical_url: Some("https://api.openai.com/v1/models".to_string()),
            critical_every_ticks: 3,
            accept_status: vec![200, 204, 206, 301, 302, 307, 308, 400, 401, 404],
            block_status: vec![403, 406, 451],
            e2e_proxy: "socks5://127.0.0.1:10808".to_string(),
            e2e_enabled: true,
            e2e_detect_intercept: true,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub fail_threshold: Option<u32>,
    pub quarantine_ms: Option<u64>,
    pub geo_quarantine_ms: Option<u64>,
    pub degrade_ms: Option<u32>,
    pub degrade_factor_pct: Option<u32>,
    pub min_switch_interval_ms: Option<u64>,
    pub switch_margin_pct: Option<u32>,
    /// Сколько тиков подряд кандидат должен быть лучше активного, прежде чем
    /// его поставят. 1 = старое поведение (переключаться по первому замеру).
    pub switch_hold_ticks: Option<u32>,
    pub recovery_probes: Option<u32>,
    pub ewma_alpha_permille: Option<u32>,
    pub stale_ms: Option<u64>,
    pub protocol_penalty_us: Option<u64>,
    pub prefer_protocol_on_block: Option<bool>,
    pub protocol_preference: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// `trace|debug|info|warn|error`
    pub level: String,
    pub format: LogFormat,
    pub stdout: bool,
    /// Append-only JSONL audit trail of every routing change.
    pub audit_path: Option<String>,
    /// `fsync` after every audit record (costs ~ms; buys crash durability).
    pub fsync_audit: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            level: "info".to_string(),
            format: LogFormat::Json,
            stdout: true,
            audit_path: Some("/var/log/watchcat/routes.jsonl".to_string()),
            fsync_audit: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    pub enabled: bool,
    /// Prometheus textfile, rewritten atomically every tick.
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        MetricsConfig {
            enabled: true,
            path: "/var/log/watchcat/metrics.prom".to_string(),
        }
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: Option<String>,
    pub chat_id: Option<String>,
    pub api_base: String,
    pub min_interval_ms: u64,
}

impl fmt::Debug for TelegramConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelegramConfig")
            .field("enabled", &self.enabled)
            .field("bot_token", &self.bot_token.as_ref().map(|_| "<redacted>"))
            .field("chat_id", &self.chat_id)
            .field("api_base", &self.api_base)
            .field("min_interval_ms", &self.min_interval_ms)
            .finish()
    }
}

/// Куда watchcat шлёт сигналы о событиях.
///
/// Демон не уведомляет сам: он отправляет факт в api, а api решает, кого и
/// когда оповещать (там же живут пороги и токен Telegram). Поэтому здесь
/// только адрес, токен и имя ноды.
#[derive(Clone, Deserialize)]
pub struct ReportingConfig {
    #[serde(default)]
    pub enabled: bool,
    /// База api, например `http://127.0.0.1:3000` или `https://api.frkn.org`.
    #[serde(default)]
    pub url: String,
    /// Токен сервиса (тот же, что у ноды для mgmt-ручек).
    #[serde(default)]
    pub token: Option<String>,
    /// Имя ноды в отчётах: по нему api ищет реестр и группирует события.
    #[serde(default)]
    pub node: String,
    #[serde(default = "default_reporting_timeout")]
    pub timeout_ms: u64,
    /// Сколько раз пробуем отправить одно событие, прежде чем уронить его.
    #[serde(default = "default_reporting_attempts")]
    pub attempts: u32,
}

fn default_reporting_timeout() -> u64 {
    5_000
}

fn default_reporting_attempts() -> u32 {
    3
}

impl fmt::Debug for ReportingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReportingConfig")
            .field("enabled", &self.enabled)
            .field("url", &self.url)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("node", &self.node)
            .field("timeout_ms", &self.timeout_ms)
            .field("attempts", &self.attempts)
            .finish()
    }
}

impl Default for ReportingConfig {
    fn default() -> Self {
        ReportingConfig {
            enabled: false,
            url: String::new(),
            token: None,
            node: String::new(),
            timeout_ms: default_reporting_timeout(),
            attempts: default_reporting_attempts(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            api: ApiConfig::default(),
            // Группы не задаются по умолчанию: пустой конфиг — ошибка запуска,
            // а не «молча управляем несуществующим main-outbound».
            selector: None,
            selectors: Vec::new(),
            probe: ProbeConfig::default(),
            policy: PolicyConfig::default(),
            logging: LoggingConfig::default(),
            metrics: MetricsConfig::default(),
            telegram: TelegramConfig {
                enabled: false,
                bot_token: None,
                chat_id: None,
                api_base: "https://api.telegram.org".to_string(),
                min_interval_ms: 3_000,
            },
            reporting: ReportingConfig::default(),
            env_overrides: Vec::new(),
            env_ignored: Vec::new(),
        }
    }
}

impl Config {
    /// Load config from `path` (or the default location), applying env overrides.
    pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
        let dotenv = load_dotenv();
        let env: BTreeMap<String, String> = std::env::vars().chain(dotenv).collect();

        let explicit = path
            .map(PathBuf::from)
            .or_else(|| env.get("WATCHCAT_CONFIG").map(PathBuf::from));

        let mut config = match &explicit {
            Some(path) => {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| ConfigError::Io(path.display().to_string(), e))?;
                Self::from_yaml(&text)?
            }
            None => {
                let default = Path::new("config.yaml");
                if default.exists() {
                    let text = std::fs::read_to_string(default)
                        .map_err(|e| ConfigError::Io(default.display().to_string(), e))?;
                    Self::from_yaml(&text)?
                } else {
                    Config::default()
                }
            }
        };

        let (applied, ignored) = config.apply_env(&env);
        config.env_overrides = applied;
        config.env_ignored = ignored;
        config.normalize();
        config.validate()?;
        Ok(config)
    }

    pub fn from_yaml(text: &str) -> Result<Config, ConfigError> {
        let mut config: Config =
            serde_yaml::from_str(text).map_err(|e| ConfigError::Yaml(e.to_string()))?;
        config.normalize();
        Ok(config)
    }

    /// Empty-string optionals mean "unset".
    ///
    /// `secret: ""` and `critical_url: ""` are what people (and `.env`
    /// templates) actually write to mean "not configured". Left as `Some("")`
    /// they would send an empty `Authorization: Bearer ` header and fail URL
    /// validation with a confusing `invalid url: ` — so both are folded to
    /// `None` here, once, for YAML and env alike.
    fn normalize(&mut self) {
        fn blank(value: &Option<String>) -> bool {
            value
                .as_deref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(false)
        }
        if blank(&self.api.secret) {
            self.api.secret = None;
        }
        if blank(&self.probe.critical_url) {
            self.probe.critical_url = None;
        }
        if blank(&self.telegram.bot_token) {
            self.telegram.bot_token = None;
        }
        if blank(&self.telegram.chat_id) {
            self.telegram.chat_id = None;
        }
    }

    /// Применяет env-оверрайды и возвращает список ключей, которые реально
    /// что-то изменили.
    ///
    /// Env существует только для разовых прогонов и отладки. На боевой ноде
    /// единственный источник правды — YAML: когда половина настроек в
    /// `/etc/watchcat/env`, а половина в `config.yaml`, ручной запуск без
    /// `set -a; . env` молча получает 401 и «ноль событий», что легко принять
    /// за здоровое состояние. Поэтому вызывающий логирует каждое
    /// переопределение.
    fn apply_env(&mut self, env: &BTreeMap<String, String>) -> (Vec<String>, Vec<String>) {
        let mut applied: Vec<String> = Vec::new();
        let mut ignored: Vec<String> = Vec::new();
        let get = |key: &str| env.get(key).map(|v| v.trim()).filter(|v| !v.is_empty());
        let get_u64 = |key: &str| get(key).and_then(|v| v.parse::<u64>().ok());
        let get_u32 = |key: &str| get(key).and_then(|v| v.parse::<u32>().ok());
        let get_bool = |key: &str| get(key).map(|v| matches!(v, "1" | "true" | "yes" | "on"));

        if let Some(v) = get("WATCHCAT_API_URL") {
            self.api.base_url = v.to_string();
            applied.push("WATCHCAT_API_URL".to_string());
        }
        if let Some(v) = get("WATCHCAT_API_SECRET") {
            self.api.secret = Some(v.to_string());
            applied.push("WATCHCAT_API_SECRET".to_string());
        }
        if let Some(v) = get_u64("WATCHCAT_API_TIMEOUT_MS") {
            self.api.timeout_ms = v;
            applied.push("WATCHCAT_API_TIMEOUT_MS".to_string());
        }
        if let Some(v) = get("WATCHCAT_SELECTOR") {
            // В мульти-групповом режиме переименовать «какую-то» группу — значит
            // тихо поменять то, чем управляем. Такой оверрайд не применяем.
            if self.selectors.is_empty() {
                self.selector.get_or_insert_with(SelectorConfig::default).tag = v.to_string();
                applied.push("WATCHCAT_SELECTOR".to_string());
            } else {
                ignored.push("WATCHCAT_SELECTOR".to_string());
            }
        }
        if let Some(v) = get_u64("WATCHCAT_INTERVAL_MS") {
            self.probe.interval_ms = v;
            applied.push("WATCHCAT_INTERVAL_MS".to_string());
        }
        if let Some(v) = get_u64("WATCHCAT_PROBE_TIMEOUT_MS") {
            self.probe.timeout_ms = v;
            applied.push("WATCHCAT_PROBE_TIMEOUT_MS".to_string());
        }
        if let Some(v) = get_u32("WATCHCAT_FAIL_THRESHOLD") {
            self.policy.fail_threshold = Some(v);
            applied.push("WATCHCAT_FAIL_THRESHOLD".to_string());
        }
        if let Some(v) = get_u64("WATCHCAT_QUARANTINE_MS") {
            self.policy.quarantine_ms = Some(v);
            applied.push("WATCHCAT_QUARANTINE_MS".to_string());
        }
        if let Some(v) = get("WATCHCAT_LOG_LEVEL") {
            self.logging.level = v.to_ascii_lowercase();
            applied.push("WATCHCAT_LOG_LEVEL".to_string());
        }
        if let Some(v) = get("WATCHCAT_AUDIT_PATH") {
            self.logging.audit_path = Some(v.to_string());
            applied.push("WATCHCAT_AUDIT_PATH".to_string());
        }
        if let Some(v) = get_bool("WATCHCAT_STDOUT") {
            self.logging.stdout = v;
            applied.push("WATCHCAT_STDOUT".to_string());
        }
        if let Some(v) = get("WATCHCAT_TELEGRAM_TOKEN") {
            self.telegram.bot_token = Some(v.to_string());
            self.telegram.enabled = true;
            applied.push("WATCHCAT_TELEGRAM_TOKEN".to_string());
        }
        if let Some(v) = get("WATCHCAT_TELEGRAM_CHAT") {
            self.telegram.chat_id = Some(v.to_string());
            applied.push("WATCHCAT_TELEGRAM_CHAT".to_string());
        }
        if let Some(v) = get("WATCHCAT_METRICS_PATH") {
            self.metrics.path = v.to_string();
            applied.push("WATCHCAT_METRICS_PATH".to_string());
        }
        if let Some(v) = get_bool("WATCHCAT_METRICS") {
            self.metrics.enabled = v;
            applied.push("WATCHCAT_METRICS".to_string());
        }

        (applied, ignored)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.reporting.enabled {
            if self.reporting.url.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "reporting: включено, но `reporting.url` пуст".to_string(),
                ));
            }
            if self.reporting.token.as_deref().unwrap_or("").is_empty() {
                return Err(ConfigError::Invalid(
                    "reporting: включено, но `reporting.token` пуст".to_string(),
                ));
            }
            if self.reporting.node.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "reporting: включено, но `reporting.node` пуст".to_string(),
                ));
            }
        }
        if self.selector.is_some() && !self.selectors.is_empty() {
            return Err(ConfigError::Invalid(
                "use either `selector:` (one group) or `selectors:` (a list), not both"
                    .to_string(),
            ));
        }
        if self.selectors.is_empty() && self.selector.is_none() {
            return Err(ConfigError::Invalid(
                "no groups configured: set `selector:` or `selectors:`".to_string(),
            ));
        }
        let mut seen: Vec<&str> = Vec::new();
        for group in &self.groups() {
            if group.tag.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "group tag must not be empty".to_string(),
                ));
            }
            if seen.contains(&group.tag.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate group tag {:?}: two supervisors on one selector fight each other",
                    group.tag
                )));
            }
            seen.push(&group.tag);
            if let Some(over) = &group.probe {
                if let Some(url) = &over.base_url {
                    Url::parse(url).map_err(|e| {
                        ConfigError::Invalid(format!("group {}: probe.base_url: {e}", group.tag))
                    })?;
                }
                if let Some(url) = &over.critical_url {
                    if !url.trim().is_empty() {
                        Url::parse(url).map_err(|e| {
                            ConfigError::Invalid(format!(
                                "group {}: probe.critical_url: {e}",
                                group.tag
                            ))
                        })?;
                    }
                }
                if let Some(proxy) = &over.e2e_proxy {
                    let proxy = Url::parse(proxy).map_err(|e| {
                        ConfigError::Invalid(format!("group {}: probe.e2e_proxy: {e}", group.tag))
                    })?;
                    if proxy.scheme != "socks5" && proxy.scheme != "socks5h" {
                        return Err(ConfigError::Invalid(format!(
                            "group {}: probe.e2e_proxy must be a socks5:// URL",
                            group.tag
                        )));
                    }
                }
            }
            if let Some(policy) = &group.policy {
                Self::apply_policy(Policy::default(), policy)
                    .validate()
                    .map_err(|e| ConfigError::Invalid(format!("group {}: {e}", group.tag)))?;
            }
            for node in &group.nodes {
                if node.tag.trim().is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "group {}: nodes[].tag must not be empty",
                        group.tag
                    )));
                }
                if let Some(protocol) = &node.protocol {
                    if Protocol::from_token(&protocol.to_ascii_lowercase()).is_none() {
                        return Err(ConfigError::Invalid(format!(
                            "group {}: nodes[{}].protocol: unknown protocol {protocol}",
                            group.tag, node.tag
                        )));
                    }
                }
            }
        }
        let api = Url::parse(&self.api.base_url)
            .map_err(|e| ConfigError::Invalid(format!("api.base_url: {e}")))?;
        if api.is_tls() {
            return Err(ConfigError::Invalid(
                "api.base_url must be plain http on loopback — sing-box's Clash API \
                 is not TLS; use an SSH tunnel for remote access"
                    .to_string(),
            ));
        }
        if self.api.timeout_ms < 50 {
            return Err(ConfigError::Invalid(
                "api.timeout_ms must be >= 50".to_string(),
            ));
        }
        if self.probe.interval_ms < 100 {
            return Err(ConfigError::Invalid(
                "probe.interval_ms must be >= 100".to_string(),
            ));
        }
        if self.probe.fast_interval_ms < 50 {
            return Err(ConfigError::Invalid(
                "probe.fast_interval_ms must be >= 50".to_string(),
            ));
        }
        if self.probe.concurrency == 0 {
            return Err(ConfigError::Invalid(
                "probe.concurrency must be >= 1".to_string(),
            ));
        }
        Url::parse(&self.probe.base_url)
            .map_err(|e| ConfigError::Invalid(format!("probe.base_url: {e}")))?;
        if let Some(critical) = &self.probe.critical_url {
            Url::parse(critical)
                .map_err(|e| ConfigError::Invalid(format!("probe.critical_url: {e}")))?;
        }
        if self.probe.method != ProbeMethod::ClashDelay {
            let proxy = Url::parse(&self.probe.e2e_proxy)
                .map_err(|e| ConfigError::Invalid(format!("probe.e2e_proxy: {e}")))?;
            if proxy.scheme != "socks5" && proxy.scheme != "socks5h" {
                return Err(ConfigError::Invalid(
                    "probe.e2e_proxy must be a socks5:// URL".to_string(),
                ));
            }
        }
        if self.telegram.enabled
            && (self.telegram.bot_token.is_none() || self.telegram.chat_id.is_none())
        {
            return Err(ConfigError::Invalid(
                "telegram.enabled requires bot_token and chat_id".to_string(),
            ));
        }
        if self.logging.audit_path.as_deref() == Some("") {
            return Err(ConfigError::Invalid(
                "logging.audit_path must not be empty (null disables the audit file)".to_string(),
            ));
        }
        self.policy().validate().map_err(ConfigError::Invalid)?;
        Ok(())
    }

    /// Effective policy (config overrides applied on top of defaults).
    pub fn policy(&self) -> Policy {
        Self::apply_policy(Policy::default(), &self.policy)
    }

    /// Групповые оверрайды ложатся поверх глобальной секции `policy`.
    pub fn policy_for(&self, group: &GroupConfig) -> Policy {
        match &group.policy {
            Some(over) => Self::apply_policy(self.policy(), over),
            None => self.policy(),
        }
    }

    fn apply_policy(mut policy: Policy, cfg: &PolicyConfig) -> Policy {
        if let Some(v) = cfg.fail_threshold {
            policy.fail_threshold = v;
        }
        if let Some(v) = cfg.quarantine_ms {
            policy.quarantine_ms = v;
        }
        if let Some(v) = cfg.geo_quarantine_ms {
            policy.geo_quarantine_ms = v;
        }
        if let Some(v) = cfg.degrade_ms {
            policy.degrade_ms = v;
        }
        if let Some(v) = cfg.degrade_factor_pct {
            policy.degrade_factor_pct = v;
        }
        if let Some(v) = cfg.min_switch_interval_ms {
            policy.min_switch_interval_ms = v;
        }
        if let Some(v) = cfg.switch_margin_pct {
            policy.switch_margin_pct = v;
        }
        if let Some(v) = cfg.switch_hold_ticks {
            policy.switch_hold_ticks = v;
        }
        if let Some(v) = cfg.recovery_probes {
            policy.recovery_probes = v;
        }
        if let Some(v) = cfg.ewma_alpha_permille {
            policy.ewma_alpha_permille = v;
        }
        if let Some(v) = cfg.stale_ms {
            policy.stale_ms = v;
        }
        if let Some(v) = cfg.protocol_penalty_us {
            policy.protocol_penalty_us = v;
        }
        if let Some(v) = cfg.prefer_protocol_on_block {
            policy.prefer_protocol_on_block = v;
        }
        if let Some(list) = &cfg.protocol_preference {
            policy.protocol_preference = list
                .iter()
                .filter_map(|name| Protocol::from_token(&name.to_ascii_lowercase()))
                .collect();
        }
        policy
    }

    /// Группы, которыми управляет процесс.
    ///
    /// `selectors:` побеждает; `selector:` — формат одной группы и остаётся
    /// валидным, чтобы старые конфиги запускались без правок.
    pub fn groups(&self) -> Vec<GroupConfig> {
        if !self.selectors.is_empty() {
            return self.selectors.clone();
        }
        self.selector.clone().map(GroupConfig::from).into_iter().collect()
    }

    /// Глобальные настройки проб с оверрайдами конкретной группы.
    pub fn probe_for(&self, group: &GroupConfig) -> ProbeConfig {
        let mut probe = self.probe.clone();
        if let Some(over) = &group.probe {
            if let Some(url) = &over.base_url {
                probe.base_url = url.clone();
            }
            if let Some(url) = &over.critical_url {
                let trimmed = url.trim();
                probe.critical_url = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
            if let Some(proxy) = &over.e2e_proxy {
                probe.e2e_proxy = proxy.clone();
            }
            if let Some(enabled) = over.e2e_enabled {
                probe.e2e_enabled = enabled;
            }
            if let Some(every) = over.critical_every_ticks {
                probe.critical_every_ticks = every;
            }
            if let Some(method) = over.method {
                probe.method = method;
            }
        }
        probe
    }

    /// Подхватывать ли чужое переключение в этой группе.
    pub fn adopt_external(&self, group: &GroupConfig) -> bool {
        group
            .adopt_external_changes
            .or_else(|| self.selector.as_ref().map(|s| s.adopt_external_changes))
            .unwrap_or(true)
    }

    /// Node specs группы; пусто — значит состав берётся из Clash API.
    pub fn node_specs_for(&self, group: &GroupConfig) -> Vec<NodeSpec> {
        group
            .nodes
            .iter()
            .map(|node| {
                let mut spec = NodeSpec::from_tag(node.tag.clone());
                if let Some(protocol) = &node.protocol {
                    if let Some(parsed) = Protocol::from_token(&protocol.to_ascii_lowercase()) {
                        spec.protocol = parsed;
                    }
                }
                if let Some(priority) = node.priority {
                    spec.priority = priority;
                }
                spec.pinned = node.pinned.unwrap_or(false);
                spec
            })
            .collect()
    }

    pub fn log_level(&self) -> crate::log::Level {
        crate::log::Level::parse(&self.logging.level).unwrap_or(crate::log::Level::Info)
    }
}

/// Read `$WATCHCAT_ENV_FILE` or `./.env` into a map. Missing file is not an
/// error: `.env` is a convenience, not a requirement.
fn load_dotenv() -> BTreeMap<String, String> {
    let path = std::env::var("WATCHCAT_ENV_FILE").unwrap_or_else(|_| ".env".to_string());
    let Ok(text) = std::fs::read_to_string(&path) else {
        return BTreeMap::new();
    };
    let mut map = BTreeMap::new();
    for line in text.lines() {
        if parse::skip_env_line(line) {
            continue;
        }
        if let Ok((_, (key, value))) = parse::env_line(line) {
            if !key.is_empty() {
                map.insert(key, value);
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_optionals_are_normalized_to_none() {
        // `secret: ""` / `critical_url: ""` is what templates leave behind;
        // they must mean "unset", not "an empty bearer token" / "invalid url".
        let config = Config::from_yaml(
            "api:\n  secret: \"\"\nselector:\n  tag: main-outbound\nprobe:\n  critical_url: \"  \"\ntelegram:\n  bot_token: \"\"\n  chat_id: \"\"\n",
        )
        .unwrap();
        assert!(config.api.secret.is_none());
        assert!(config.probe.critical_url.is_none());
        assert!(config.telegram.bot_token.is_none());
        assert!(config.telegram.chat_id.is_none());
        assert!(config.validate().is_ok(), "empty optionals must validate");
    }

    /// Конфиг с одной группой — база для тестов, которым группа не важна.
    fn with_group() -> Config {
        let mut config = Config::default();
        config.selector = Some(SelectorConfig {
            tag: "main-outbound".to_string(),
            nodes: Vec::new(),
            adopt_external_changes: true,
        });
        config
    }

    const MINIMAL: &str = r#"
api:
  base_url: "http://127.0.0.1:9090"
  secret: "s3cr3t"
selector:
  tag: main-outbound
  nodes:
    - tag: node-01-fr-vless
    - tag: node-02-de-hysteria
      protocol: hysteria2
      priority: 10
      pinned: true
probe:
  interval_ms: 5000
  critical_url: "https://api.openai.com/v1/models"
policy:
  fail_threshold: 2
  quarantine_ms: 300000
"#;

    #[test]
    fn parses_minimal_yaml() {
        let config = Config::from_yaml(MINIMAL).unwrap();
        assert_eq!(config.groups()[0].tag, "main-outbound");
        assert_eq!(config.groups()[0].nodes.len(), 2);
        assert_eq!(config.probe.interval_ms, 5000);
        let policy = config.policy();
        assert_eq!(policy.fail_threshold, 2);
        assert_eq!(policy.quarantine_ms, 300_000);
        // untouched defaults survive
        assert_eq!(policy.switch_margin_pct, 20);
        assert_eq!(policy.recovery_probes, 2);
    }

    #[test]
    fn derives_node_specs_from_tags_and_overrides() {
        let config = Config::from_yaml(MINIMAL).unwrap();
        let specs = config.node_specs_for(&config.groups()[0]);
        assert_eq!(specs[0].protocol, Protocol::Vless);
        assert_eq!(specs[0].index, Some(1));
        assert_eq!(specs[1].protocol, Protocol::Hysteria2);
        assert_eq!(specs[1].priority, 10);
        assert!(specs[1].pinned);
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = Config::from_yaml("policy:\n  quarantine_secs: 300\n").unwrap_err();
        assert!(matches!(err, ConfigError::Yaml(_)));
    }

    #[test]
    fn rejects_empty_selector() {
        let mut config = with_group();
        config.selector.as_mut().unwrap().tag = "  ".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_tls_api_and_bad_urls() {
        let mut config = Config::default();
        config.api.base_url = "https://127.0.0.1:9090".to_string();
        assert!(config.validate().is_err());
        let mut config = Config::default();
        config.probe.base_url = "not a url".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_unknown_protocol_name() {
        let yaml = "selector:\n  nodes:\n    - tag: node-01-fr-vless\n      protocol: wireguard9\n";
        let config = Config::from_yaml(yaml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn telegram_requires_credentials() {
        let mut config = with_group();
        config.telegram.enabled = true;
        assert!(config.validate().is_err());
        config.telegram.bot_token = Some("t".into());
        config.telegram.chat_id = Some("1".into());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn env_overrides_win() {
        let mut config = Config::from_yaml(MINIMAL).unwrap();
        let mut env = BTreeMap::new();
        env.insert("WATCHCAT_API_SECRET".to_string(), "from-env".to_string());
        env.insert("WATCHCAT_INTERVAL_MS".to_string(), "1000".to_string());
        env.insert("WATCHCAT_SELECTOR".to_string(), "other".to_string());
        let (applied, ignored) = config.apply_env(&env);
        assert_eq!(
            applied,
            vec![
                "WATCHCAT_API_SECRET".to_string(),
                "WATCHCAT_SELECTOR".to_string(),
                "WATCHCAT_INTERVAL_MS".to_string(),
            ]
        );
        assert!(ignored.is_empty());
        assert_eq!(config.api.secret.as_deref(), Some("from-env"));
        assert_eq!(config.probe.interval_ms, 1000);
        assert_eq!(config.groups()[0].tag, "other");
    }

    /// Боевой сценарий: секрет в YAML, env пустой. Ни одного оверрайда,
    /// секрет доехал до ApiConfig.
    #[test]
    fn secret_from_yaml_without_env() {
        let mut config = Config::from_yaml(MINIMAL).unwrap();
        let (applied, ignored) = config.apply_env(&BTreeMap::new());
        assert!(applied.is_empty(), "env не должен ничего перекрывать");
        assert!(ignored.is_empty());
        config.normalize();
        assert_eq!(config.api.secret.as_deref(), Some("s3cr3t"));
        assert!(config.validate().is_ok());
    }

    // ---------------------------------------------------------------- multi-group

    const TWO_GROUPS: &str = r#"
api:
  base_url: "http://127.0.0.1:9090"
  secret: "s3cr3t"
selectors:
  - tag: fr-exit
    policy:
      switch_hold_ticks: 6
      switch_margin_pct: 30
  - tag: bt-exit
    probe:
      base_url: "https://www.gstatic.com/generate_204"
      critical_url: ""
      e2e_enabled: false
"#;

    #[test]
    fn parses_two_groups() {
        let config = Config::from_yaml(TWO_GROUPS).unwrap();
        config.validate().unwrap();
        let groups = config.groups();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].tag, "fr-exit");
        assert_eq!(groups[1].tag, "bt-exit");
    }

    /// Групповые оверрайды не должны протекать в соседнюю группу.
    #[test]
    fn group_overrides_are_isolated() {
        let config = Config::from_yaml(TWO_GROUPS).unwrap();
        let groups = config.groups();

        let fr = config.policy_for(&groups[0]);
        let bt = config.policy_for(&groups[1]);
        assert_eq!(fr.switch_hold_ticks, 6);
        assert_eq!(fr.switch_margin_pct, 30);
        // bt-exit ничего не переопределяла — только дефолты
        assert_eq!(bt.switch_hold_ticks, Policy::default().switch_hold_ticks);
        assert_eq!(bt.switch_margin_pct, Policy::default().switch_margin_pct);

        let bt_probe = config.probe_for(&groups[1]);
        assert_eq!(bt_probe.base_url, "https://www.gstatic.com/generate_204");
        assert!(bt_probe.critical_url.is_none(), "пустая строка = выключено");
        assert!(!bt_probe.e2e_enabled);

        let fr_probe = config.probe_for(&groups[0]);
        assert_eq!(fr_probe.base_url, config.probe.base_url);
        assert!(fr_probe.e2e_enabled);
    }

    #[test]
    fn selector_and_selectors_together_is_an_error() {
        let yaml = format!(
            "{}selector:\n  tag: legacy\n",
            TWO_GROUPS
        );
        let config = Config::from_yaml(&yaml).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("not both"), "{err}");
    }

    #[test]
    fn duplicate_group_tags_are_rejected() {
        let yaml = TWO_GROUPS.replace("tag: bt-exit", "tag: fr-exit");
        let config = Config::from_yaml(&yaml).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate group tag"), "{err}");
    }

    /// Старый конфиг с одним `selector:` работает без правок и превращается
    /// в одну группу.
    #[test]
    fn legacy_selector_is_one_group() {
        let config = Config::from_yaml(MINIMAL).unwrap();
        config.validate().unwrap();
        let groups = config.groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].tag, "main-outbound");
        assert_eq!(config.probe_for(&groups[0]).interval_ms, 5000);
    }

    /// В мульти-групповом режиме `WATCHCAT_SELECTOR` переименовал бы «какую-то»
    /// группу — такой оверрайд игнорируется и попадает в отчёт.
    #[test]
    fn env_selector_ignored_in_multi_group() {
        let mut config = Config::from_yaml(TWO_GROUPS).unwrap();
        let mut env = BTreeMap::new();
        env.insert("WATCHCAT_SELECTOR".to_string(), "renamed".to_string());
        let (applied, ignored) = config.apply_env(&env);
        assert!(applied.is_empty());
        assert_eq!(ignored, vec!["WATCHCAT_SELECTOR".to_string()]);
        assert_eq!(config.groups()[0].tag, "fr-exit");
    }

    #[test]
    fn protocol_preference_parses_names() {
        let mut config = Config::default();
        config.policy.protocol_preference = Some(vec![
            "hysteria2".into(),
            "vless-reality".into(),
            "nonsense".into(),
        ]);
        let policy = config.policy();
        assert_eq!(
            policy.protocol_preference,
            vec![Protocol::Hysteria2, Protocol::VlessReality]
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let config = Config::from_yaml(
            "api:\n  secret: super-secret-value\ntelegram:\n  bot_token: tg-token-value\n",
        )
        .unwrap();
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret-value"));
        assert!(!rendered.contains("tg-token-value"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn cli_path_missing_file_is_an_error() {
        let err = Config::load(Some(Path::new("/nonexistent/watchcat.yaml"))).unwrap_err();
        assert!(matches!(err, ConfigError::Io(_, _)));
    }
}
