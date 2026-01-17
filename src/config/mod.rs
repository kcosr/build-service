use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::logging::LoggingSettings;

const DEFAULT_CONFIG_PATH: &str = "/etc/build-service/config.toml";
const DEFAULT_SCHEMA_VERSION: &str = "2";

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
    pub projects: Vec<ProjectConfig>,

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

        self.service.validate()?;
        self.build.validate()?;
        self.artifacts.validate()?;
        self.validate_projects()?;

        if let Err(err) = LoggingSettings::from_config(&self.logging) {
            return Err(ConfigError::Invalid(format!("{err}")));
        }

        Ok(())
    }

    fn validate_projects(&self) -> Result<(), ConfigError> {
        if self.projects.is_empty() {
            return Err(ConfigError::Invalid(
                "projects must include at least one project".to_string(),
            ));
        }

        let mut seen = HashSet::new();
        for project in &self.projects {
            let id = project.id().trim();
            if id.is_empty() {
                return Err(ConfigError::Invalid(
                    "projects contains an empty id".to_string(),
                ));
            }
            if !seen.insert(id.to_string()) {
                return Err(ConfigError::Invalid(format!(
                    "projects contains duplicate id {id}"
                )));
            }

            if project.commands().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "project {id} must allow at least one command"
                )));
            }

            for command in project.commands() {
                if command.trim().is_empty() {
                    return Err(ConfigError::Invalid(format!(
                        "project {id} contains an empty command name"
                    )));
                }
                if !self.build.commands.contains_key(command) {
                    return Err(ConfigError::Invalid(format!(
                        "project {id} references undefined command {command}"
                    )));
                }
            }

            for pattern in project.artifacts() {
                validate_artifact_pattern(pattern)
                    .map_err(|err| ConfigError::Invalid(format!("project {id}: {err}")))?;
            }

            match project {
                ProjectConfig::Repo {
                    repo_url,
                    repo_ref,
                    repo_subdir,
                    ..
                } => {
                    if repo_url.trim().is_empty() {
                        return Err(ConfigError::Invalid(format!(
                            "project {id} repo_url must not be empty"
                        )));
                    }
                    if repo_ref.trim().is_empty() {
                        return Err(ConfigError::Invalid(format!(
                            "project {id} repo_ref must not be empty"
                        )));
                    }
                    validate_relative_path(repo_subdir).map_err(|err| {
                        ConfigError::Invalid(format!("project {id} repo_subdir {err}"))
                    })?;
                }
                ProjectConfig::Path { path_root, .. } => {
                    if !path_root.is_absolute() {
                        return Err(ConfigError::Invalid(format!(
                            "project {id} path_root must be an absolute path"
                        )));
                    }
                }
            }
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

impl ServiceConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.socket.enabled {
            self.socket.validate()?;
        }

        if self.http.enabled {
            self.http.validate()?;
        }

        Ok(())
    }
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

    #[serde(default)]
    pub auth: TokenAuthConfig,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            enabled: default_socket_enabled(),
            path: default_socket_path(),
            group: default_socket_group(),
            mode: default_socket_mode(),
            auth: TokenAuthConfig::default(),
        }
    }
}

impl SocketConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.group.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "service.socket.group must not be empty".to_string(),
            ));
        }

        if !self.path.is_absolute() {
            return Err(ConfigError::Invalid(
                "service.socket.path must be an absolute path".to_string(),
            ));
        }

        self.parse_mode()
            .map_err(|e| ConfigError::Invalid(e.to_string()))?;

        self.auth
            .validate("service.socket.auth")
            .map_err(ConfigError::Invalid)?;

        Ok(())
    }

    pub fn parse_mode(&self) -> Result<u32, SocketModeError> {
        parse_socket_mode(&self.mode)
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

    #[serde(default = "default_http_listen_addr")]
    pub listen_addr: String,

    #[serde(default)]
    pub auth: HttpAuthConfig,

    #[serde(default)]
    pub tls: HttpTlsConfig,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: default_http_enabled(),
            listen_addr: default_http_listen_addr(),
            auth: HttpAuthConfig::default(),
            tls: HttpTlsConfig::default(),
        }
    }
}

impl HttpConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_addr.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "service.http.listen_addr must not be empty".to_string(),
            ));
        }

        if self.listen_addr.parse::<SocketAddr>().is_err() {
            return Err(ConfigError::Invalid(
                "service.http.listen_addr must be a valid socket address".to_string(),
            ));
        }

        self.auth
            .validate("service.http.auth")
            .map_err(ConfigError::Invalid)?;

        if self.auth.r#type != "bearer" {
            return Err(ConfigError::Invalid(
                "service.http.auth.type must be bearer".to_string(),
            ));
        }

        if self.tls.enabled {
            let cert = self.tls.cert_path.as_ref().ok_or_else(|| {
                ConfigError::Invalid(
                    "service.http.tls.cert_path must be set when tls is enabled".to_string(),
                )
            })?;
            let key = self.tls.key_path.as_ref().ok_or_else(|| {
                ConfigError::Invalid(
                    "service.http.tls.key_path must be set when tls is enabled".to_string(),
                )
            })?;

            if !cert.is_absolute() {
                return Err(ConfigError::Invalid(
                    "service.http.tls.cert_path must be an absolute path".to_string(),
                ));
            }
            if !key.is_absolute() {
                return Err(ConfigError::Invalid(
                    "service.http.tls.key_path must be an absolute path".to_string(),
                ));
            }
            if let Some(ca_path) = &self.tls.ca_path {
                if !ca_path.is_absolute() {
                    return Err(ConfigError::Invalid(
                        "service.http.tls.ca_path must be an absolute path".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

fn default_http_enabled() -> bool {
    false
}

fn default_http_listen_addr() -> String {
    "0.0.0.0:8080".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAuthConfig {
    #[serde(default = "default_http_auth_type")]
    pub r#type: String,

    #[serde(default)]
    pub required: bool,

    #[serde(default)]
    pub tokens: Vec<String>,
}

impl Default for HttpAuthConfig {
    fn default() -> Self {
        Self {
            r#type: default_http_auth_type(),
            required: false,
            tokens: Vec::new(),
        }
    }
}

impl HttpAuthConfig {
    fn validate(&self, label: &str) -> Result<(), String> {
        if self.required && self.tokens.is_empty() {
            return Err(format!("{label}.tokens must not be empty when required"));
        }

        for token in &self.tokens {
            if token.trim().is_empty() {
                return Err(format!("{label}.tokens must not include empty values"));
            }
        }

        Ok(())
    }
}

fn default_http_auth_type() -> String {
    "bearer".to_string()
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenAuthConfig {
    #[serde(default)]
    pub required: bool,

    #[serde(default)]
    pub tokens: Vec<String>,
}

impl TokenAuthConfig {
    fn validate(&self, label: &str) -> Result<(), String> {
        if self.required && self.tokens.is_empty() {
            return Err(format!("{label}.tokens must not be empty when required"));
        }

        for token in &self.tokens {
            if token.trim().is_empty() {
                return Err(format!("{label}.tokens must not include empty values"));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    #[serde(default = "default_workspace_root")]
    pub workspace_root: PathBuf,

    #[serde(default)]
    pub run_as_user: Option<String>,

    #[serde(default)]
    pub run_as_group: Option<String>,

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
            run_as_user: None,
            run_as_group: None,
            commands: default_build_commands(),
            timeouts: BuildTimeoutsConfig::default(),
            environment: BuildEnvironmentConfig::default(),
        }
    }
}

impl BuildConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.workspace_root.is_absolute() {
            return Err(ConfigError::Invalid(
                "build.workspace_root must be an absolute path".to_string(),
            ));
        }

        if self.timeouts.default_sec == 0 || self.timeouts.max_sec == 0 {
            return Err(ConfigError::Invalid(
                "build.timeouts values must be greater than zero".to_string(),
            ));
        }

        if self.timeouts.default_sec > self.timeouts.max_sec {
            return Err(ConfigError::Invalid(
                "build.timeouts.default_sec must be <= build.timeouts.max_sec".to_string(),
            ));
        }

        if let Some(user) = &self.run_as_user {
            if user.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "build.run_as_user must not be empty".to_string(),
                ));
            }
        }

        if let Some(group) = &self.run_as_group {
            if group.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "build.run_as_group must not be empty".to_string(),
                ));
            }
        }

        if self.commands.is_empty() {
            return Err(ConfigError::Invalid(
                "build.commands must include at least one command".to_string(),
            ));
        }

        for (name, path) in &self.commands {
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

        for entry in &self.environment.allow {
            if entry.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "build.environment.allow must not contain empty entries".to_string(),
                ));
            }
        }

        Ok(())
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
pub struct ArtifactsConfig {
    #[serde(default)]
    pub storage_root: PathBuf,

    #[serde(default)]
    pub public_base_url: String,

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
            public_base_url: String::new(),
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

        if self.public_base_url.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "artifacts.public_base_url must not be empty".to_string(),
            ));
        }

        match url::Url::parse(&self.public_base_url) {
            Ok(url) => {
                let scheme = url.scheme();
                if scheme != "http" && scheme != "https" {
                    return Err(ConfigError::Invalid(
                        "artifacts.public_base_url must use http or https".to_string(),
                    ));
                }
            }
            Err(err) => {
                return Err(ConfigError::Invalid(format!(
                    "artifacts.public_base_url is invalid: {err}"
                )));
            }
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

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProjectConfig {
    Repo {
        id: String,
        repo_url: String,
        #[serde(default = "default_repo_ref")]
        repo_ref: String,
        #[serde(default = "default_repo_subdir")]
        repo_subdir: String,
        #[serde(default)]
        commands: Vec<String>,
        #[serde(default)]
        artifacts: Vec<String>,
    },
    Path {
        id: String,
        path_root: PathBuf,
        #[serde(default)]
        commands: Vec<String>,
        #[serde(default)]
        artifacts: Vec<String>,
    },
}

impl ProjectConfig {
    pub fn id(&self) -> &str {
        match self {
            ProjectConfig::Repo { id, .. } => id,
            ProjectConfig::Path { id, .. } => id,
        }
    }

    pub fn commands(&self) -> &[String] {
        match self {
            ProjectConfig::Repo { commands, .. } => commands,
            ProjectConfig::Path { commands, .. } => commands,
        }
    }

    pub fn artifacts(&self) -> &[String] {
        match self {
            ProjectConfig::Repo { artifacts, .. } => artifacts,
            ProjectConfig::Path { artifacts, .. } => artifacts,
        }
    }
}

fn default_repo_ref() -> String {
    "main".to_string()
}

fn default_repo_subdir() -> String {
    "./".to_string()
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

fn validate_artifact_pattern(pattern: &str) -> Result<(), String> {
    if pattern.trim().is_empty() {
        return Err("artifact pattern must not be empty".to_string());
    }

    let path = Path::new(pattern);
    if path.is_absolute() {
        return Err("artifact pattern must be relative".to_string());
    }

    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err("artifact pattern must not include ..".to_string());
        }
    }

    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("must not be empty".to_string());
    }

    let rel = Path::new(path);
    if rel.is_absolute() {
        return Err("must be relative".to_string());
    }

    for component in rel.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err("must not include ..".to_string());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config(command_path: PathBuf) -> Config {
        let mut commands = HashMap::new();
        commands.insert("make".to_string(), command_path);

        Config {
            schema_version: DEFAULT_SCHEMA_VERSION.to_string(),
            service: ServiceConfig::default(),
            build: BuildConfig {
                workspace_root: PathBuf::from("/tmp"),
                run_as_user: None,
                run_as_group: None,
                commands,
                timeouts: BuildTimeoutsConfig::default(),
                environment: BuildEnvironmentConfig::default(),
            },
            artifacts: ArtifactsConfig {
                storage_root: PathBuf::from("/tmp/artifacts"),
                public_base_url: "https://example.com/artifacts".to_string(),
                ttl_sec: None,
                gc_interval_sec: None,
                max_bytes: None,
            },
            projects: vec![ProjectConfig::Path {
                id: "project".to_string(),
                path_root: PathBuf::from("/tmp/workspace"),
                commands: vec!["make".to_string()],
                artifacts: vec!["out/bin".to_string()],
            }],
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
        config.schema_version = "1".to_string();
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("unsupported schema_version"));
    }

    #[test]
    fn validate_rejects_no_transport_enabled() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cmd = temp.path().join("make");
        std::fs::write(&cmd, "").expect("write");

        let mut config = base_config(cmd);
        config.service.socket.enabled = false;
        config.service.http.enabled = false;
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("service.socket.enabled"));
    }

    #[test]
    fn validate_rejects_relative_socket_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cmd = temp.path().join("make");
        std::fs::write(&cmd, "").expect("write");

        let mut config = base_config(cmd);
        config.service.socket.path = PathBuf::from("relative.sock");
        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("socket.path"));
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

    #[test]
    fn validate_rejects_invalid_artifact_pattern() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cmd = temp.path().join("make");
        std::fs::write(&cmd, "").expect("write");

        let mut config = base_config(cmd);
        config.projects = vec![ProjectConfig::Path {
            id: "project".to_string(),
            path_root: PathBuf::from("/tmp/workspace"),
            commands: vec!["make".to_string()],
            artifacts: vec!["../oops".to_string()],
        }];

        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("artifact pattern"));
    }

    #[test]
    fn validate_rejects_project_missing_command() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cmd = temp.path().join("make");
        std::fs::write(&cmd, "").expect("write");

        let mut config = base_config(cmd);
        config.projects = vec![ProjectConfig::Path {
            id: "project".to_string(),
            path_root: PathBuf::from("/tmp/workspace"),
            commands: vec!["ninja".to_string()],
            artifacts: vec![],
        }];

        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("undefined command"));
    }

    #[test]
    fn validate_rejects_http_auth_without_tokens() {
        let temp = tempfile::tempdir().expect("tempdir");
        let cmd = temp.path().join("make");
        std::fs::write(&cmd, "").expect("write");

        let mut config = base_config(cmd);
        config.service.http.enabled = true;
        config.service.http.auth.required = true;
        config.service.http.auth.tokens.clear();

        let err = config.validate().expect_err("should fail");
        assert!(err.to_string().contains("service.http.auth.tokens"));
    }
}
