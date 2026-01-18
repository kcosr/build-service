use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::logging::LoggingSettings;

const DEFAULT_CONFIG_PATH: &str = "/etc/build-service/config.toml";
const DEFAULT_SCHEMA_VERSION: &str = "3";
const DEFAULT_MAX_UPLOAD_BYTES: u64 = 134_217_728;
const DEFAULT_MAX_EXTRACTED_BYTES: u64 = DEFAULT_MAX_UPLOAD_BYTES * 10;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse config {path}: {source}")]
    ParseToml {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigPathKind {
    Explicit,
    Env,
    Default,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    #[serde(default)]
    pub service: ServiceConfig,

    #[serde(default)]
    pub build: BuildConfig,

    #[serde(default)]
    pub artifacts: ArtifactsConfig,

    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Config {
    pub fn load_from_sources(cli_path: Option<&Path>) -> Result<Self, ConfigError> {
        let (path, _kind) = Self::resolve_path(cli_path);
        let raw = fs::read_to_string(&path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;

        let mut config: Config = toml::from_str(&raw).map_err(|source| ConfigError::ParseToml {
            path: path.clone(),
            source,
        })?;

        config.apply_env_overrides();
        config.validate()?;

        Ok(config)
    }

    pub fn resolve_path(cli_path: Option<&Path>) -> (PathBuf, ConfigPathKind) {
        if let Some(p) = cli_path {
            (p.to_path_buf(), ConfigPathKind::Explicit)
        } else if let Ok(env_path) = env::var("BUILD_SERVICE_CONFIG") {
            (PathBuf::from(env_path), ConfigPathKind::Env)
        } else {
            (PathBuf::from(DEFAULT_CONFIG_PATH), ConfigPathKind::Default)
        }
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(level) = env::var("BUILD_SERVICE_LOG_LEVEL") {
            if !level.trim().is_empty() {
                self.logging.level = level;
            }
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != DEFAULT_SCHEMA_VERSION {
            return Err(ConfigError::Invalid(format!(
                "unsupported schema_version {}, expected {}",
                self.schema_version, DEFAULT_SCHEMA_VERSION
            )));
        }

        if !self.service.socket.enabled && !self.service.http.enabled {
            return Err(ConfigError::Invalid(
                "at least one of service.socket.enabled or service.http.enabled must be true"
                    .to_string(),
            ));
        }

        if self.service.socket.enabled {
            if self.service.socket.group.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "service.socket.group must not be empty".to_string(),
                ));
            }

            if !self.service.socket.path.is_absolute() {
                return Err(ConfigError::Invalid(
                    "service.socket.path must be an absolute path".to_string(),
                ));
            }

            self.service
                .socket
                .parse_mode()
                .map_err(|e| ConfigError::Invalid(e.to_string()))?;
        }

        if self.service.http.enabled {
            if self.service.http.listen_addr.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "service.http.listen_addr must not be empty".to_string(),
                ));
            }

            if self.service.http.auth.required && self.service.http.auth.tokens.is_empty() {
                return Err(ConfigError::Invalid(
                    "service.http.auth.tokens must not be empty when auth is required".to_string(),
                ));
            }

            if self.service.http.auth.auth_type != "bearer" {
                return Err(ConfigError::Invalid(
                    "service.http.auth.type must be 'bearer'".to_string(),
                ));
            }
        }

        if !self.build.workspace_root.is_absolute() {
            return Err(ConfigError::Invalid(
                "build.workspace_root must be an absolute path".to_string(),
            ));
        }

        if self.build.max_upload_bytes == 0 {
            return Err(ConfigError::Invalid(
                "build.max_upload_bytes must be greater than zero".to_string(),
            ));
        }

        if self.build.max_extracted_bytes == 0 {
            return Err(ConfigError::Invalid(
                "build.max_extracted_bytes must be greater than zero".to_string(),
            ));
        }

        if self.build.timeouts.default_sec == 0 || self.build.timeouts.max_sec == 0 {
            return Err(ConfigError::Invalid(
                "build.timeouts values must be greater than zero".to_string(),
            ));
        }

        if self.build.timeouts.default_sec > self.build.timeouts.max_sec {
            return Err(ConfigError::Invalid(
                "build.timeouts.default_sec must be <= build.timeouts.max_sec".to_string(),
            ));
        }

        if self.build.commands.is_empty() {
            return Err(ConfigError::Invalid(
                "build.commands must include at least one command".to_string(),
            ));
        }

        for (name, path) in &self.build.commands {
            if name.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "build.commands contains an empty command name".to_string(),
                ));
            }
            if !path.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "build.commands.{name} must be an absolute path"
                )));
            }
            if !path.exists() {
                return Err(ConfigError::Invalid(format!(
                    "build.commands.{name} does not exist at {path:?}"
                )));
            }
        }

        if let Some(user) = &self.build.run_as_user {
            if user.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "build.run_as_user must not be empty".to_string(),
                ));
            }
        }

        if let Some(group) = &self.build.run_as_group {
            if group.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "build.run_as_group must not be empty".to_string(),
                ));
            }
        }

        for entry in &self.build.environment.allow {
            if entry.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "build.environment.allow must not contain empty entries".to_string(),
                ));
            }
        }

        self.artifacts.validate()?;

        if let Err(err) = LoggingSettings::from_config(&self.logging) {
            return Err(ConfigError::Invalid(format!("{err}")));
        }

        Ok(())
    }
}

fn default_schema_version() -> String {
    DEFAULT_SCHEMA_VERSION.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceConfig {
    #[serde(default)]
    pub socket: SocketConfig,

    #[serde(default)]
    pub http: HttpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketConfig {
    #[serde(default = "default_socket_enabled")]
    pub enabled: bool,

    #[serde(default = "default_socket_path")]
    pub path: PathBuf,

    #[serde(default = "default_socket_group")]
    pub group: String,

    #[serde(default = "default_socket_mode")]
    pub mode: String,
}

impl SocketConfig {
    pub fn parse_mode(&self) -> Result<u32, SocketModeError> {
        parse_socket_mode(&self.mode)
    }
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            enabled: default_socket_enabled(),
            path: default_socket_path(),
            group: default_socket_group(),
            mode: default_socket_mode(),
        }
    }
}

fn default_socket_enabled() -> bool {
    true
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/build-service.sock")
}

fn default_socket_group() -> String {
    "users".to_string()
}

fn default_socket_mode() -> String {
    "0660".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    #[serde(default = "default_http_enabled")]
    pub enabled: bool,

    #[serde(default = "default_http_listen")]
    pub listen_addr: String,

    #[serde(default)]
    pub auth: HttpAuthConfig,

    #[serde(default)]
    pub tls: HttpTlsConfig,
}

fn default_http_enabled() -> bool {
    false
}

fn default_http_listen() -> String {
    "0.0.0.0:8080".to_string()
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: default_http_enabled(),
            listen_addr: default_http_listen(),
            auth: HttpAuthConfig::default(),
            tls: HttpTlsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAuthConfig {
    #[serde(default = "default_http_auth_type", rename = "type")]
    pub auth_type: String,

    #[serde(default)]
    pub required: bool,

    #[serde(default)]
    pub tokens: Vec<String>,
}

fn default_http_auth_type() -> String {
    "bearer".to_string()
}

impl Default for HttpAuthConfig {
    fn default() -> Self {
        Self {
            auth_type: default_http_auth_type(),
            required: false,
            tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpTlsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub cert_path: Option<PathBuf>,

    #[serde(default)]
    pub key_path: Option<PathBuf>,

    #[serde(default)]
    pub ca_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    #[serde(default = "default_workspace_root")]
    pub workspace_root: PathBuf,

    #[serde(default)]
    pub run_as_user: Option<String>,

    #[serde(default)]
    pub run_as_group: Option<String>,

    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: u64,

    #[serde(default = "default_max_extracted_bytes")]
    pub max_extracted_bytes: u64,

    #[serde(default)]
    pub commands: HashMap<String, PathBuf>,

    #[serde(default)]
    pub timeouts: TimeoutConfig,

    #[serde(default)]
    pub environment: EnvironmentConfig,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            workspace_root: default_workspace_root(),
            run_as_user: None,
            run_as_group: None,
            max_upload_bytes: default_max_upload_bytes(),
            max_extracted_bytes: default_max_extracted_bytes(),
            commands: HashMap::new(),
            timeouts: TimeoutConfig::default(),
            environment: EnvironmentConfig::default(),
        }
    }
}

fn default_workspace_root() -> PathBuf {
    PathBuf::from("/var/lib/build-service/workspaces")
}

fn default_max_upload_bytes() -> u64 {
    DEFAULT_MAX_UPLOAD_BYTES
}

fn default_max_extracted_bytes() -> u64 {
    DEFAULT_MAX_EXTRACTED_BYTES
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    #[serde(default = "default_timeout_sec")]
    pub default_sec: u64,

    #[serde(default = "default_timeout_sec")]
    pub max_sec: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            default_sec: default_timeout_sec(),
            max_sec: default_timeout_sec(),
        }
    }
}

fn default_timeout_sec() -> u64 {
    600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentConfig {
    #[serde(default = "default_allowed_env")]
    pub allow: Vec<String>,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            allow: default_allowed_env(),
        }
    }
}

fn default_allowed_env() -> Vec<String> {
    vec![
        "PATH".to_string(),
        "HOME".to_string(),
        "USER".to_string(),
        "LOGNAME".to_string(),
        "LANG".to_string(),
        "CC".to_string(),
        "CXX".to_string(),
        "CFLAGS".to_string(),
        "CXXFLAGS".to_string(),
        "LDFLAGS".to_string(),
        "PKG_CONFIG_PATH".to_string(),
        "MAKEFLAGS".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactsConfig {
    #[serde(default)]
    pub storage_root: PathBuf,

    #[serde(default)]
    pub ttl_sec: Option<u64>,

    #[serde(default)]
    pub gc_interval_sec: Option<u64>,

    #[serde(default)]
    pub max_bytes: Option<u64>,
}

impl Default for ArtifactsConfig {
    fn default() -> Self {
        Self {
            storage_root: PathBuf::new(),
            ttl_sec: None,
            gc_interval_sec: None,
            max_bytes: None,
        }
    }
}

impl ArtifactsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.storage_root.as_os_str().is_empty() {
            return Err(ConfigError::Invalid(
                "artifacts.storage_root must not be empty".to_string(),
            ));
        }

        if !self.storage_root.is_absolute() {
            return Err(ConfigError::Invalid(
                "artifacts.storage_root must be an absolute path".to_string(),
            ));
        }

        if let Some(ttl) = self.ttl_sec {
            if ttl == 0 {
                return Err(ConfigError::Invalid(
                    "artifacts.ttl_sec must be greater than zero".to_string(),
                ));
            }
        }

        if let Some(interval) = self.gc_interval_sec {
            if interval == 0 {
                return Err(ConfigError::Invalid(
                    "artifacts.gc_interval_sec must be greater than zero".to_string(),
                ));
            }
        }

        if let Some(max_bytes) = self.max_bytes {
            if max_bytes == 0 {
                return Err(ConfigError::Invalid(
                    "artifacts.max_bytes must be greater than zero".to_string(),
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default)]
    pub directory: Option<PathBuf>,

    #[serde(default = "default_logging_level")]
    pub level: String,

    #[serde(default = "default_logging_max_bytes")]
    pub max_bytes: u64,

    #[serde(default = "default_logging_max_files")]
    pub max_files: usize,

    #[serde(default = "default_logging_console")]
    pub console: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            directory: None,
            level: default_logging_level(),
            max_bytes: default_logging_max_bytes(),
            max_files: default_logging_max_files(),
            console: default_logging_console(),
        }
    }
}

fn default_logging_level() -> String {
    "info".to_string()
}

fn default_logging_max_bytes() -> u64 {
    104_857_600
}

fn default_logging_max_files() -> usize {
    5
}

fn default_logging_console() -> bool {
    true
}

#[derive(Debug, thiserror::Error)]
pub enum SocketModeError {
    #[error("socket mode must be a 4-digit octal string")]
    InvalidLength,

    #[error("socket mode must be octal digits")]
    InvalidDigit,
}

fn parse_socket_mode(mode: &str) -> Result<u32, SocketModeError> {
    let value = mode.trim();
    if value.len() != 4 {
        return Err(SocketModeError::InvalidLength);
    }

    let digits = value.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(0);
    }

    let parsed = u32::from_str_radix(digits, 8).map_err(|_| SocketModeError::InvalidDigit)?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_socket_mode_accepts_octal() {
        assert_eq!(parse_socket_mode("0660").unwrap(), 0o660);
    }

    #[test]
    fn parse_socket_mode_rejects_short() {
        let err = parse_socket_mode("660").unwrap_err();
        assert!(matches!(err, SocketModeError::InvalidLength));
    }

    #[test]
    fn validate_requires_service_enabled() {
        let mut config = Config {
            schema_version: DEFAULT_SCHEMA_VERSION.to_string(),
            service: ServiceConfig::default(),
            build: BuildConfig::default(),
            artifacts: ArtifactsConfig::default(),
            logging: LoggingConfig::default(),
        };

        config.service.socket.enabled = false;
        config.service.http.enabled = false;

        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("service.socket.enabled"));
    }
}
