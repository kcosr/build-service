use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::logging::LoggingSettings;

const DEFAULT_CONFIG_PATH: &str = "/etc/build-service/config.toml";
const DEFAULT_SCHEMA_VERSION: &str = "1";

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

        if self.service.socket_group.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "service.socket_group must not be empty".to_string(),
            ));
        }

        if !self.service.socket_path.is_absolute() {
            return Err(ConfigError::Invalid(
                "service.socket_path must be an absolute path".to_string(),
            ));
        }

        self.service
            .parse_socket_mode()
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;

        if !self.build.workspace_root.is_absolute() {
            return Err(ConfigError::Invalid(
                "build.workspace_root must be an absolute path".to_string(),
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

        for entry in &self.build.environment.allow {
            if entry.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "build.environment.allow must not contain empty entries".to_string(),
                ));
            }
        }

        if let Err(err) = LoggingSettings::from_config(&self.logging) {
            return Err(ConfigError::Invalid(format!("{err}")));
        }

        Ok(())
    }
}

fn default_schema_version() -> String {
    DEFAULT_SCHEMA_VERSION.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    #[serde(default = "default_socket_group")]
    pub socket_group: String,

    #[serde(default = "default_socket_mode")]
    pub socket_mode: String,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            socket_group: default_socket_group(),
            socket_mode: default_socket_mode(),
        }
    }
}

impl ServiceConfig {
    pub fn parse_socket_mode(&self) -> Result<u32, SocketModeError> {
        parse_socket_mode(&self.socket_mode)
    }
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
pub struct BuildConfig {
    #[serde(default = "default_workspace_root")]
    pub workspace_root: PathBuf,

    #[serde(default = "default_build_commands")]
    pub commands: HashMap<String, PathBuf>,

    #[serde(default)]
    pub timeouts: BuildTimeoutsConfig,

    #[serde(default)]
    pub environment: BuildEnvironmentConfig,
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self {
            workspace_root: default_workspace_root(),
            commands: default_build_commands(),
            timeouts: BuildTimeoutsConfig::default(),
            environment: BuildEnvironmentConfig::default(),
        }
    }
}

fn default_workspace_root() -> PathBuf {
    PathBuf::from("/home")
}

fn default_build_commands() -> HashMap<String, PathBuf> {
    let mut commands = HashMap::new();
    commands.insert("make".to_string(), PathBuf::from("/usr/bin/make"));
    commands
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildTimeoutsConfig {
    #[serde(default = "default_timeout_default_sec")]
    pub default_sec: u64,

    #[serde(default = "default_timeout_max_sec")]
    pub max_sec: u64,
}

impl Default for BuildTimeoutsConfig {
    fn default() -> Self {
        Self {
            default_sec: default_timeout_default_sec(),
            max_sec: default_timeout_max_sec(),
        }
    }
}

fn default_timeout_default_sec() -> u64 {
    600
}

fn default_timeout_max_sec() -> u64 {
    1800
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildEnvironmentConfig {
    #[serde(default = "default_env_allow")]
    pub allow: Vec<String>,
}

impl Default for BuildEnvironmentConfig {
    fn default() -> Self {
        Self {
            allow: default_env_allow(),
        }
    }
}

fn default_env_allow() -> Vec<String> {
    vec![
        "PATH".to_string(),
        "HOME".to_string(),
        "USER".to_string(),
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
#[error("invalid socket_mode {value}, expected octal like 0660")]
pub struct SocketModeError {
    value: String,
}

fn parse_socket_mode(value: &str) -> Result<u32, SocketModeError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SocketModeError {
            value: value.to_string(),
        });
    }

    let digits = trimmed.trim_start_matches("0o").trim_start_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };

    let parsed = u32::from_str_radix(digits, 8).map_err(|_| SocketModeError {
        value: value.to_string(),
    })?;

    if parsed > 0o7777 {
        return Err(SocketModeError {
            value: value.to_string(),
        });
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base_config(command_path: PathBuf) -> Config {
        let mut commands = HashMap::new();
        commands.insert("make".to_string(), command_path);

        Config {
            schema_version: DEFAULT_SCHEMA_VERSION.to_string(),
            service: ServiceConfig::default(),
            build: BuildConfig {
                workspace_root: PathBuf::from("/tmp"),
                commands,
                timeouts: BuildTimeoutsConfig::default(),
                environment: BuildEnvironmentConfig::default(),
            },
            logging: LoggingConfig::default(),
        }
    }

    #[test]
    fn parse_socket_mode_accepts_octal() {
        assert_eq!(parse_socket_mode("0660").unwrap(), 0o660);
        assert_eq!(parse_socket_mode("660").unwrap(), 0o660);
        assert_eq!(parse_socket_mode("0o660").unwrap(), 0o660);
        assert_eq!(parse_socket_mode("0").unwrap(), 0);
    }

    #[test]
    fn parse_socket_mode_rejects_invalid() {
        assert!(parse_socket_mode("").is_err());
        assert!(parse_socket_mode("xyz").is_err());
        assert!(parse_socket_mode("0888").is_err());
    }

    #[test]
    fn validate_rejects_schema_version() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cmd = temp.path().join("make");
        std::fs::write(&cmd, "").expect("write");

        let mut config = base_config(cmd);
        config.schema_version = "2".to_string();
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("unsupported schema_version"));
    }

    #[test]
    fn validate_rejects_relative_socket_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cmd = temp.path().join("make");
        std::fs::write(&cmd, "").expect("write");

        let mut config = base_config(cmd);
        config.service.socket_path = PathBuf::from("relative.sock");
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("socket_path"));
    }

    #[test]
    fn validate_rejects_missing_command_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("missing-make");
        let config = base_config(missing);
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn validate_rejects_timeout_order() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cmd = temp.path().join("make");
        std::fs::write(&cmd, "").expect("write");

        let mut config = base_config(cmd);
        config.build.timeouts.default_sec = 10;
        config.build.timeouts.max_sec = 5;
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("default_sec"));
    }

    #[test]
    fn validate_rejects_empty_env_allow() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cmd = temp.path().join("make");
        std::fs::write(&cmd, "").expect("write");

        let mut config = base_config(cmd);
        config.build.environment.allow.push(String::new());
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("environment.allow"));
    }
}
