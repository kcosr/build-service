use std::collections::{HashMap, VecDeque};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::Client;
use serde::Deserialize;
use tempfile::NamedTempFile;
use zip::write::FileOptions;
use zip::ZipWriter;

use build_service::protocol::{
    ArtifactArchive, ArtifactSpec, Request, ResponseEvent, SCHEMA_VERSION,
};
use build_service::validation::{validate_relative_path, validate_relative_pattern};

const DEFAULT_SOCKET_PATH: &str = "/run/build-service.sock";
const CLIENT_CONFIG_DIR: &str = ".build-service";
const CLIENT_CONFIG_FILE: &str = "config.toml";
const CONNECTION_FALLBACK_EXIT_CODE: u8 = 222;
const OUTPUT_PREFIX: &str = "[build-service]";
const STDOUT_MAX_LINES_ENV: &str = "BUILD_SERVICE_STDOUT_MAX_LINES";
const STDERR_MAX_LINES_ENV: &str = "BUILD_SERVICE_STDERR_MAX_LINES";

#[derive(Debug, Parser)]
#[command(author, version, about = "Client for the build-service daemon")]
struct Args {
    #[arg(long)]
    timeout: Option<u64>,

    #[arg(long, help = "Endpoint URL (http://, https://, or unix://)")]
    endpoint: Option<String>,

    #[arg(long)]
    token: Option<String>,

    #[arg(long)]
    request_id: Option<String>,

    #[arg(required = true)]
    command: String,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ClientConfig {
    sources: PatternConfig,
    artifacts: PatternConfig,
    #[serde(default)]
    request: Option<RequestConfig>,
    #[serde(default)]
    connection: Option<ConnectionConfig>,
    #[serde(default)]
    output: Option<OutputConfig>,
}

#[derive(Debug, Deserialize, Default)]
struct PatternConfig {
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RequestConfig {
    #[serde(default)]
    timeout_sec: Option<u64>,
    #[serde(default)]
    env: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
struct ConnectionConfig {
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    local_fallback: bool,
}

#[derive(Debug, Deserialize, Default)]
struct OutputConfig {
    #[serde(default)]
    stdout_max_lines: Option<usize>,
    #[serde(default)]
    stderr_max_lines: Option<usize>,
    #[serde(default)]
    stdout_tail_lines: usize,
    #[serde(default)]
    stderr_tail_lines: usize,
}

#[derive(Debug, Clone)]
enum Endpoint {
    Http { base: String },
    Unix { path: PathBuf },
}

#[derive(Debug)]
enum BuildError {
    ConnectionFailed(String),
    Other(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::ConnectionFailed(msg) | BuildError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

fn connection_failure_exit_code(local_fallback: bool) -> u8 {
    if local_fallback {
        CONNECTION_FALLBACK_EXIT_CODE
    } else {
        1
    }
}

fn is_connection_failure(err: &reqwest::Error) -> bool {
    if err.is_connect() || err.is_timeout() {
        return true;
    }

    let mut source = err.source();
    while let Some(cause) = source {
        if let Some(io_err) = cause.downcast_ref::<io::Error>() {
            match io_err.kind() {
                io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::NotConnected
                | io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::TimedOut
                | io::ErrorKind::NotFound
                | io::ErrorKind::PermissionDenied => {
                    return true;
                }
                _ => {}
            }
        }
        source = cause.source();
    }

    false
}

#[derive(Debug, Default, Clone, Copy)]
struct OutputLimits {
    stdout_max_lines: Option<usize>,
    stderr_max_lines: Option<usize>,
    stdout_tail_lines: usize,
    stderr_tail_lines: usize,
}

fn resolve_output_limits(config: Option<&OutputConfig>) -> io::Result<OutputLimits> {
    let stdout_max_lines = if let Ok(raw) = env::var(STDOUT_MAX_LINES_ENV) {
        parse_output_limit(&raw, STDOUT_MAX_LINES_ENV)?
            .or_else(|| config.and_then(|config| config.stdout_max_lines))
    } else {
        config.and_then(|config| config.stdout_max_lines)
    };

    let stderr_max_lines = if let Ok(raw) = env::var(STDERR_MAX_LINES_ENV) {
        parse_output_limit(&raw, STDERR_MAX_LINES_ENV)?
            .or_else(|| config.and_then(|config| config.stderr_max_lines))
    } else {
        config.and_then(|config| config.stderr_max_lines)
    };

    let stdout_tail_lines = config
        .map(|config| config.stdout_tail_lines)
        .unwrap_or_default();
    let stderr_tail_lines = config
        .map(|config| config.stderr_tail_lines)
        .unwrap_or_default();

    Ok(OutputLimits {
        stdout_max_lines,
        stderr_max_lines,
        stdout_tail_lines,
        stderr_tail_lines,
    })
}

fn parse_output_limit(raw: &str, var: &str) -> io::Result<Option<usize>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let parsed: usize = trimmed.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{var} must be a non-negative integer, got {trimmed}"),
        )
    })?;
    Ok(Some(parsed))
}

struct OutputLimiter {
    stdout: LineLimiter,
    stderr: LineLimiter,
}

impl OutputLimiter {
    fn new(limits: OutputLimits) -> Self {
        Self {
            stdout: LineLimiter::new(
                "stdout",
                STDOUT_MAX_LINES_ENV,
                limits.stdout_max_lines,
                limits.stdout_tail_lines,
            ),
            stderr: LineLimiter::new(
                "stderr",
                STDERR_MAX_LINES_ENV,
                limits.stderr_max_lines,
                limits.stderr_tail_lines,
            ),
        }
    }

    fn write_stdout(&mut self, data: &str) -> io::Result<()> {
        let mut stdout = io::stdout();
        self.stdout.write_chunk(data, &mut stdout)
    }

    fn write_stderr(&mut self, data: &str) -> io::Result<()> {
        let mut stderr = io::stderr();
        self.stderr.write_chunk(data, &mut stderr)
    }

    fn finish(&mut self) -> io::Result<()> {
        self.stdout.finish();
        self.stderr.finish();
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        self.stdout.write_summary(&mut stdout, "stdout")?;
        self.stderr.write_summary(&mut stderr, "stderr")?;
        stdout.flush()?;
        stderr.flush()?;
        Ok(())
    }
}

struct LineLimiter {
    label: &'static str,
    env_var: &'static str,
    max_lines: Option<usize>,
    tail_lines: usize,
    printed_lines: usize,
    suppressed_lines: usize,
    at_line_start: bool,
    current_line_allowed: bool,
    suppression_notified: bool,
    suppressed_line: String,
    tail_buffer: VecDeque<String>,
}

impl LineLimiter {
    fn new(
        label: &'static str,
        env_var: &'static str,
        max_lines: Option<usize>,
        tail_lines: usize,
    ) -> Self {
        Self {
            label,
            env_var,
            max_lines,
            tail_lines,
            printed_lines: 0,
            suppressed_lines: 0,
            at_line_start: true,
            current_line_allowed: true,
            suppression_notified: false,
            suppressed_line: String::new(),
            tail_buffer: VecDeque::new(),
        }
    }

    fn write_chunk(&mut self, data: &str, writer: &mut dyn Write) -> io::Result<()> {
        if self.max_lines.is_none() {
            writer.write_all(data.as_bytes())?;
            writer.flush()?;
            return Ok(());
        }

        let mut output = String::new();
        for segment in data.split_inclusive('\n') {
            if self.at_line_start {
                self.current_line_allowed = self
                    .max_lines
                    .map(|max| self.printed_lines < max)
                    .unwrap_or(true);
                self.at_line_start = false;

                if !self.current_line_allowed && !self.suppression_notified {
                    output.push_str(&format!(
                        "{OUTPUT_PREFIX} suppressing {} output due to limits (increase output lines with {}=<lines>)\n",
                        self.label,
                        self.env_var
                    ));
                    self.suppression_notified = true;
                }
            }

            if self.current_line_allowed {
                output.push_str(segment);
            } else if self.tail_lines > 0 {
                self.suppressed_line.push_str(segment);
            }

            if segment.ends_with('\n') {
                self.finish_line();
            }
        }

        if !output.is_empty() {
            writer.write_all(output.as_bytes())?;
            writer.flush()?;
        }

        Ok(())
    }

    fn finish(&mut self) {
        if self.max_lines.is_none() {
            return;
        }

        if !self.at_line_start {
            if self.current_line_allowed {
                self.printed_lines += 1;
            } else {
                self.suppressed_lines += 1;
                self.push_tail_line();
            }
            self.suppressed_line.clear();
            self.at_line_start = true;
        }
    }

    fn write_summary(&self, writer: &mut dyn Write, label: &str) -> io::Result<()> {
        if self.max_lines.is_none() || self.suppressed_lines == 0 {
            return Ok(());
        }

        writeln!(
            writer,
            "{OUTPUT_PREFIX} {} more {} lines suppressed",
            self.suppressed_lines, label
        )?;

        if !self.tail_buffer.is_empty() {
            for line in &self.tail_buffer {
                writer.write_all(line.as_bytes())?;
            }
        }

        Ok(())
    }

    fn finish_line(&mut self) {
        if self.current_line_allowed {
            self.printed_lines += 1;
        } else {
            self.suppressed_lines += 1;
            self.push_tail_line();
        }
        self.suppressed_line.clear();
        self.at_line_start = true;
    }

    fn push_tail_line(&mut self) {
        if self.tail_lines == 0 {
            return;
        }

        self.tail_buffer.push_back(self.suppressed_line.clone());
        if self.tail_buffer.len() > self.tail_lines {
            self.tail_buffer.pop_front();
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();

    let repo_root = match find_repo_root() {
        Ok(root) => root,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    let config_path = repo_root.join(CLIENT_CONFIG_DIR).join(CLIENT_CONFIG_FILE);
    let client_config = match load_client_config(&config_path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    if let Err(err) = validate_patterns(&client_config.sources, "sources") {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    if let Err(err) = validate_patterns(&client_config.artifacts, "artifacts") {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    if client_config.sources.include.is_empty() {
        eprintln!("sources.include must not be empty");
        return ExitCode::from(1);
    }

    let source_archive = match build_source_archive(&repo_root, &client_config.sources) {
        Ok(archive) => archive,
        Err(err) => {
            eprintln!("failed to package sources: {err}");
            return ExitCode::from(1);
        }
    };

    let cwd = match resolve_relative_cwd(&repo_root) {
        Ok(cwd) => cwd,
        Err(err) => {
            eprintln!("failed to resolve cwd: {err}");
            return ExitCode::from(1);
        }
    };

    let artifacts = ArtifactSpec {
        include: client_config.artifacts.include,
        exclude: client_config.artifacts.exclude,
    };

    let env = client_config
        .request
        .as_ref()
        .map(|request| request.env.clone())
        .filter(|env| !env.is_empty());

    let timeout_sec = match resolve_timeout(args.timeout, client_config.request.as_ref()) {
        Ok(timeout) => timeout,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    let request = Request {
        schema_version: Some(SCHEMA_VERSION.to_string()),
        request_id: args.request_id,
        command: args.command,
        args: args.args,
        cwd,
        timeout_sec,
        artifacts,
        env,
    };

    let connection = client_config.connection.as_ref();
    let endpoint = match resolve_endpoint(args.endpoint, connection) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let token = resolve_token(args.token, connection);
    let output_limits = match resolve_output_limits(client_config.output.as_ref()) {
        Ok(limits) => limits,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    let build = match run_build(
        &request,
        &source_archive,
        &endpoint,
        token.as_deref(),
        &output_limits,
    ) {
        Ok(result) => result,
        Err(err) => match err {
            BuildError::ConnectionFailed(msg) => {
                eprintln!("build request failed: {msg}");
                let local_fallback = connection.map(|c| c.local_fallback).unwrap_or(false);
                return ExitCode::from(connection_failure_exit_code(local_fallback));
            }
            BuildError::Other(msg) => {
                eprintln!("build request failed: {msg}");
                return ExitCode::from(1);
            }
        },
    };

    if build.exit_code != 0 {
        return to_exit_code(build.exit_code, build.timed_out);
    }

    if let Some(archive) = build.artifacts {
        if let Err(err) = download_and_extract(&archive, &endpoint, token.as_deref(), &repo_root) {
            eprintln!("failed to fetch artifacts: {err}");
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}

fn find_repo_root() -> io::Result<PathBuf> {
    let mut dir = env::current_dir()?;
    loop {
        let candidate = dir.join(CLIENT_CONFIG_DIR).join(CLIENT_CONFIG_FILE);
        if candidate.exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            break;
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{} not found in current directory or parents",
            Path::new(CLIENT_CONFIG_DIR)
                .join(CLIENT_CONFIG_FILE)
                .display()
        ),
    ))
}

fn load_client_config(path: &Path) -> io::Result<ClientConfig> {
    let raw = fs::read_to_string(path)?;
    toml::from_str(&raw).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn validate_patterns(patterns: &PatternConfig, label: &str) -> io::Result<()> {
    for pattern in &patterns.include {
        let field = format!("{label}.include");
        validate_relative_pattern(pattern, &field)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    }
    for pattern in &patterns.exclude {
        let field = format!("{label}.exclude");
        validate_relative_pattern(pattern, &field)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    }
    Ok(())
}

fn resolve_relative_cwd(root: &Path) -> io::Result<Option<String>> {
    let cwd = env::current_dir()?;
    let rel = cwd
        .strip_prefix(root)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "cwd is outside repo root"))?;

    if rel.as_os_str().is_empty() {
        return Ok(None);
    }

    let rel_str = rel.to_string_lossy().into_owned();
    validate_relative_path(&rel_str, "cwd")
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    Ok(Some(rel_str))
}

fn build_source_archive(root: &Path, patterns: &PatternConfig) -> io::Result<NamedTempFile> {
    let root = fs::canonicalize(root)?;
    let mut matched_files: HashMap<PathBuf, PathBuf> = HashMap::new();
    let exclude_patterns = compile_patterns(&patterns.exclude)?;

    for pattern in &patterns.include {
        let pattern_root = root.join(pattern).to_string_lossy().into_owned();
        let entries = glob::glob(&pattern_root)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

        let _ = collect_recursive_prefix(pattern, &root, &exclude_patterns, &mut matched_files)?;

        for entry in entries {
            let path = entry.map_err(|err| io::Error::other(err.to_string()))?;
            let canonical = fs::canonicalize(&path)?;

            if !canonical.starts_with(&root) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("path {canonical:?} is outside repo root"),
                ));
            }

            if canonical.is_dir() {
                collect_dir_files(&canonical, &root, &exclude_patterns, &mut matched_files)?;
            } else if canonical.is_file() {
                let rel = canonical
                    .strip_prefix(&root)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))?
                    .to_path_buf();
                if !is_excluded(&rel, &exclude_patterns) {
                    matched_files.entry(canonical).or_insert(rel);
                }
            }
        }
    }

    if matched_files.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no source files matched",
        ));
    }

    let temp = tempfile::Builder::new()
        .prefix("build-service-src-")
        .suffix(".zip")
        .tempfile()?;

    write_zip(&temp, &matched_files)?;
    Ok(temp)
}

fn collect_recursive_prefix(
    pattern: &str,
    root: &Path,
    exclude_patterns: &[glob::Pattern],
    matched_files: &mut HashMap<PathBuf, PathBuf>,
) -> io::Result<bool> {
    let base = if pattern == "**" {
        Some("")
    } else {
        pattern
            .strip_suffix("/**")
            .or_else(|| pattern.strip_suffix("\\**"))
    };

    let Some(base) = base else {
        return Ok(false);
    };

    let base_path = if base.is_empty() {
        root.to_path_buf()
    } else {
        root.join(base)
    };

    if !base_path.exists() {
        return Ok(false);
    }

    let canonical = fs::canonicalize(&base_path)?;
    if !canonical.starts_with(root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("path {canonical:?} is outside repo root"),
        ));
    }

    if canonical.is_dir() {
        collect_dir_files(&canonical, root, exclude_patterns, matched_files)?;
        return Ok(true);
    }

    Ok(false)
}

fn compile_patterns(patterns: &[String]) -> io::Result<Vec<glob::Pattern>> {
    let mut compiled = Vec::new();
    for pattern in patterns {
        let glob = glob::Pattern::new(pattern)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        compiled.push(glob);
    }
    Ok(compiled)
}

fn collect_dir_files(
    dir: &Path,
    root: &Path,
    exclude_patterns: &[glob::Pattern],
    matched_files: &mut HashMap<PathBuf, PathBuf>,
) -> io::Result<()> {
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.map_err(|err| io::Error::other(err.to_string()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let canonical = fs::canonicalize(entry.path())?;
        if !canonical.starts_with(root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path {canonical:?} is outside repo root"),
            ));
        }
        let rel = canonical
            .strip_prefix(root)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid path"))?
            .to_path_buf();
        if is_excluded(&rel, exclude_patterns) {
            continue;
        }
        matched_files.entry(canonical).or_insert(rel);
    }
    Ok(())
}

fn is_excluded(path: &Path, patterns: &[glob::Pattern]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    let path_str = path.to_string_lossy();
    patterns.iter().any(|pattern| pattern.matches(&path_str))
}

fn write_zip(temp: &NamedTempFile, matched_files: &HashMap<PathBuf, PathBuf>) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let file = temp.reopen()?;
    let mut zip = ZipWriter::new(file);

    let mut items: Vec<_> = matched_files.iter().collect();
    items.sort_by(|a, b| a.1.cmp(b.1));

    for (source, rel) in items {
        let name = rel.to_string_lossy().replace('\\', "/");

        // Preserve file permissions in the zip
        let metadata = fs::metadata(source)?;
        let mode = metadata.permissions().mode();

        let options = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(mode);

        zip.start_file(name, options).map_err(io::Error::other)?;
        let mut input = fs::File::open(source)?;
        io::copy(&mut input, &mut zip)?;
    }

    zip.finish().map_err(io::Error::other)?;
    Ok(())
}

fn parse_endpoint(raw: &str) -> io::Result<Endpoint> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "endpoint must not be empty",
        ));
    }

    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        let scheme_pos = trimmed.find("://").unwrap_or(0);
        let after_scheme = &trimmed[scheme_pos + 3..];
        if after_scheme.is_empty() || after_scheme.chars().all(|c| c == '/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "http endpoint must include a host",
            ));
        }
        let base = trimmed.trim_end_matches('/').to_string();
        return Ok(Endpoint::Http { base });
    }

    if let Some(path_str) = trimmed.strip_prefix("unix://") {
        if path_str.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unix endpoint must include an absolute path",
            ));
        }
        let path = PathBuf::from(path_str);
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unix endpoint path must be absolute",
            ));
        }
        return Ok(Endpoint::Unix { path });
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "endpoint must start with http://, https://, or unix://",
    ))
}

fn resolve_endpoint(
    explicit: Option<String>,
    config: Option<&ConnectionConfig>,
) -> io::Result<Endpoint> {
    if let Some(endpoint) = explicit {
        if !endpoint.trim().is_empty() {
            return parse_endpoint(&endpoint);
        }
    }

    if let Ok(env_endpoint) = env::var("BUILD_SERVICE_ENDPOINT") {
        if !env_endpoint.trim().is_empty() {
            return parse_endpoint(&env_endpoint);
        }
    }

    if let Some(connection) = config {
        if let Some(endpoint) = &connection.endpoint {
            if !endpoint.trim().is_empty() {
                return parse_endpoint(endpoint);
            }
        }
    }

    let default_endpoint = format!("unix://{DEFAULT_SOCKET_PATH}");
    parse_endpoint(&default_endpoint)
}

fn resolve_timeout(
    explicit: Option<u64>,
    request: Option<&RequestConfig>,
) -> io::Result<Option<u64>> {
    if let Some(timeout) = explicit {
        if timeout == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "timeout must be greater than zero",
            ));
        }
        return Ok(Some(timeout));
    }

    if let Ok(env_timeout) = env::var("BUILD_SERVICE_TIMEOUT") {
        let trimmed = env_timeout.trim();
        if !trimmed.is_empty() {
            let parsed: u64 = trimmed.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("BUILD_SERVICE_TIMEOUT must be a positive integer, got {trimmed}"),
                )
            })?;
            if parsed == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "BUILD_SERVICE_TIMEOUT must be greater than zero",
                ));
            }
            return Ok(Some(parsed));
        }
    }

    if let Some(request) = request {
        if let Some(timeout) = request.timeout_sec {
            if timeout == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "request.timeout_sec must be greater than zero",
                ));
            }
            return Ok(Some(timeout));
        }
    }

    Ok(None)
}

fn resolve_token(explicit: Option<String>, config: Option<&ConnectionConfig>) -> Option<String> {
    if let Some(token) = explicit {
        if !token.trim().is_empty() {
            return Some(token);
        }
    }

    if let Ok(env_token) = env::var("BUILD_SERVICE_TOKEN") {
        if !env_token.trim().is_empty() {
            return Some(env_token);
        }
    }

    if let Some(connection) = config {
        if let Some(token) = &connection.token {
            if !token.trim().is_empty() {
                return Some(token.clone());
            }
        }
    }

    None
}

struct BuildResult {
    exit_code: i32,
    timed_out: bool,
    artifacts: Option<ArtifactArchive>,
}

fn run_build(
    request: &Request,
    source_archive: &NamedTempFile,
    endpoint: &Endpoint,
    token: Option<&str>,
    output_limits: &OutputLimits,
) -> Result<BuildResult, BuildError> {
    let (client, url, send_auth) = match endpoint {
        Endpoint::Http { base } => (
            Client::builder()
                .timeout(None)
                .build()
                .map_err(|err| BuildError::Other(format!("failed to create client: {err}")))?,
            format!("{base}/v1/builds"),
            true,
        ),
        Endpoint::Unix { path } => {
            let client = Client::builder()
                .unix_socket(path.clone())
                .timeout(None)
                .build()
                .map_err(|err| BuildError::Other(format!("failed to create client: {err}")))?;
            (client, "http://localhost/v1/builds".to_string(), false)
        }
    };

    let metadata = serde_json::to_string(request)
        .map_err(|err| BuildError::Other(format!("failed to serialize request: {err}")))?;
    let source_part = Part::file(source_archive.path())
        .map_err(|err| BuildError::Other(format!("failed to read source archive: {err}")))?;
    let form = Form::new()
        .part(
            "metadata",
            Part::text(metadata).mime_str("application/json").unwrap(),
        )
        .part("source", source_part.mime_str("application/zip").unwrap());

    let mut builder = client.post(url).multipart(form);
    if send_auth {
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
    }

    let response = match builder.send() {
        Ok(response) => response,
        Err(err) => {
            if is_connection_failure(&err) {
                return Err(BuildError::ConnectionFailed(format!(
                    "cannot reach endpoint: {err}"
                )));
            }
            return Err(BuildError::Other(format!("request failed: {err}")));
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_else(|_| "".to_string());
        return Err(BuildError::Other(format!(
            "server returned {status}: {body}"
        )));
    }

    read_responses(response, output_limits)
}

fn read_responses(
    response: reqwest::blocking::Response,
    output_limits: &OutputLimits,
) -> Result<BuildResult, BuildError> {
    let mut reader = BufReader::new(response);
    let mut line = String::new();
    let mut exit_code: Option<i32> = None;
    let mut timed_out = false;
    let mut artifacts: Option<ArtifactArchive> = None;
    let mut output = OutputLimiter::new(*output_limits);

    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|err| BuildError::Other(format!("failed to read response: {err}")))?;
        if bytes == 0 {
            break;
        }

        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }

        let event: ResponseEvent = serde_json::from_str(trimmed)
            .map_err(|err| BuildError::Other(format!("invalid response format: {err}")))?;

        match event {
            ResponseEvent::Stdout { data } => {
                output
                    .write_stdout(&data)
                    .map_err(|err| BuildError::Other(format!("failed to write stdout: {err}")))?;
            }
            ResponseEvent::Stderr { data } => {
                output
                    .write_stderr(&data)
                    .map_err(|err| BuildError::Other(format!("failed to write stderr: {err}")))?;
            }
            ResponseEvent::Error { message, .. } => {
                if let Some(message) = message {
                    let mut stderr = io::stderr();
                    writeln!(stderr, "{message}").map_err(|err| {
                        BuildError::Other(format!("failed to write error: {err}"))
                    })?;
                }
            }
            ResponseEvent::Exit {
                code,
                timed_out: timed,
                artifacts: event_artifacts,
            } => {
                exit_code = Some(code);
                timed_out = timed;
                artifacts = event_artifacts;
                break;
            }
            ResponseEvent::Build { .. } => {}
        }
    }

    output
        .finish()
        .map_err(|err| BuildError::Other(format!("failed to flush output: {err}")))?;

    match exit_code {
        Some(code) => Ok(BuildResult {
            exit_code: code,
            timed_out,
            artifacts,
        }),
        None => Err(BuildError::Other("missing exit event".to_string())),
    }
}

fn download_and_extract(
    archive: &ArtifactArchive,
    endpoint: &Endpoint,
    token: Option<&str>,
    repo_root: &Path,
) -> io::Result<()> {
    let (client, url, send_auth) = match endpoint {
        Endpoint::Http { base } => (
            Client::builder().build().map_err(io::Error::other)?,
            build_artifact_url(base, &archive.path),
            true,
        ),
        Endpoint::Unix { path } => {
            let client = Client::builder()
                .unix_socket(path.clone())
                .build()
                .map_err(io::Error::other)?;
            (
                client,
                build_artifact_url("http://localhost", &archive.path),
                false,
            )
        }
    };

    let mut builder = client.get(url);
    if send_auth {
        if let Some(token) = token {
            builder = builder.bearer_auth(token);
        }
    }

    let mut response = builder.send().map_err(io::Error::other)?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_else(|_| "".to_string());
        return Err(io::Error::other(format!(
            "artifact download failed {status}: {body}"
        )));
    }

    let temp = tempfile::Builder::new()
        .prefix("build-service-artifacts-")
        .suffix(".zip")
        .tempfile()?;
    let mut file = temp.reopen()?;
    io::copy(&mut response, &mut file)?;

    extract_zip(temp.path(), repo_root)
}

fn build_artifact_url(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        return path.to_string();
    }

    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

fn extract_zip(zip_path: &Path, dest: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(file)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let Some(enclosed) = file.enclosed_name() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "zip entry had invalid path",
            ));
        };

        let out_path = dest.join(enclosed);
        let unix_mode = file.unix_mode();

        if file.is_dir() {
            fs::create_dir_all(&out_path)?;
            continue;
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut outfile = fs::File::create(&out_path)?;
        io::copy(&mut file, &mut outfile)?;

        // Restore Unix permissions if present in zip
        if let Some(mode) = unix_mode {
            fs::set_permissions(&out_path, fs::Permissions::from_mode(mode))?;
        }
    }

    Ok(())
}

fn to_exit_code(code: i32, timed_out: bool) -> ExitCode {
    if timed_out {
        return ExitCode::from(124);
    }
    ExitCode::from(normalize_exit_code(code))
}

fn normalize_exit_code(code: i32) -> u8 {
    if code < 0 {
        return 1;
    }
    if code > u8::MAX as i32 {
        return u8::MAX;
    }
    code as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::time::Duration;
    use tempfile::tempdir;
    use zip::ZipArchive;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn normalize_exit_code_clamps() {
        assert_eq!(normalize_exit_code(-1), 1);
        assert_eq!(normalize_exit_code(0), 0);
        assert_eq!(normalize_exit_code(255), 255);
        assert_eq!(normalize_exit_code(300), 255);
    }

    #[test]
    fn connection_failure_exit_code_respects_fallback() {
        assert_eq!(
            connection_failure_exit_code(true),
            CONNECTION_FALLBACK_EXIT_CODE
        );
        assert_eq!(connection_failure_exit_code(false), 1);
    }

    #[test]
    fn is_connection_failure_detects_refused_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let client = Client::builder()
            .timeout(Duration::from_secs(1))
            .build()
            .unwrap();
        let err = client.get(format!("http://{addr}")).send().unwrap_err();
        assert!(is_connection_failure(&err));
    }

    #[test]
    fn build_source_archive_skips_unmatched_patterns() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path();
        fs::create_dir_all(root.join("src")).expect("create src dir");
        fs::write(root.join("src/main.rs"), "fn main() {}").expect("write file");

        let patterns = PatternConfig {
            include: vec!["src/**".to_string(), "tests/**".to_string()],
            exclude: Vec::new(),
        };

        let archive = build_source_archive(root, &patterns).expect("archive");
        let file = fs::File::open(archive.path()).expect("open zip");
        let archive = ZipArchive::new(file).expect("read zip");
        assert!(archive.len() > 0, "archive should have entries");
    }

    #[test]
    fn line_limiter_suppresses_and_prints_tail() {
        let mut limiter = LineLimiter::new("stdout", STDOUT_MAX_LINES_ENV, Some(2), 2);
        let mut output = Vec::new();

        limiter.write_chunk("one\n", &mut output).unwrap();
        limiter
            .write_chunk("two\nthree\nfour\n", &mut output)
            .unwrap();
        limiter.finish();
        limiter.write_summary(&mut output, "stdout").unwrap();

        let rendered = String::from_utf8(output).unwrap();
        assert_eq!(
            rendered,
            "one\ntwo\n[build-service] suppressing stdout output due to limits (increase output lines with BUILD_SERVICE_STDOUT_MAX_LINES=<lines>)\n[build-service] 2 more stdout lines suppressed\nthree\nfour\n"
        );
    }

    #[test]
    fn line_limiter_zero_limit_prints_only_summary_and_tail() {
        let mut limiter = LineLimiter::new("stderr", STDERR_MAX_LINES_ENV, Some(0), 1);
        let mut output = Vec::new();

        limiter.write_chunk("one\ntwo\n", &mut output).unwrap();
        limiter.finish();
        limiter.write_summary(&mut output, "stderr").unwrap();

        let rendered = String::from_utf8(output).unwrap();
        assert_eq!(
            rendered,
            "[build-service] suppressing stderr output due to limits (increase output lines with BUILD_SERVICE_STDERR_MAX_LINES=<lines>)\n[build-service] 2 more stderr lines suppressed\ntwo\n"
        );
    }

    #[test]
    fn line_limiter_no_suppression_skips_summary() {
        let mut limiter = LineLimiter::new("stdout", STDOUT_MAX_LINES_ENV, Some(5), 3);
        let mut output = Vec::new();

        limiter.write_chunk("one\ntwo\n", &mut output).unwrap();
        limiter.finish();
        limiter.write_summary(&mut output, "stdout").unwrap();

        let rendered = String::from_utf8(output).unwrap();
        assert_eq!(rendered, "one\ntwo\n");
    }

    #[test]
    fn parse_endpoint_requires_scheme() {
        assert!(parse_endpoint("localhost:8080").is_err());
        assert!(parse_endpoint("unix://relative/path").is_err());
    }

    #[test]
    fn parse_endpoint_accepts_http_https_unix() {
        let http = parse_endpoint("http://example.com:8080").unwrap();
        match http {
            Endpoint::Http { base } => assert_eq!(base, "http://example.com:8080"),
            _ => panic!("expected http endpoint"),
        }

        let https = parse_endpoint("https://example.com/").unwrap();
        match https {
            Endpoint::Http { base } => assert_eq!(base, "https://example.com"),
            _ => panic!("expected https endpoint"),
        }

        let unix = parse_endpoint("unix:///run/build-service.sock").unwrap();
        match unix {
            Endpoint::Unix { path } => {
                assert_eq!(path, PathBuf::from("/run/build-service.sock"))
            }
            _ => panic!("expected unix endpoint"),
        }
    }

    #[test]
    fn resolve_output_limits_prefers_env_then_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev_stdout = env::var(STDOUT_MAX_LINES_ENV).ok();
        let prev_stderr = env::var(STDERR_MAX_LINES_ENV).ok();

        env::remove_var(STDOUT_MAX_LINES_ENV);
        env::remove_var(STDERR_MAX_LINES_ENV);

        let config = OutputConfig {
            stdout_max_lines: Some(5),
            stderr_max_lines: Some(6),
            stdout_tail_lines: 1,
            stderr_tail_lines: 2,
        };

        let limits = resolve_output_limits(Some(&config)).unwrap();
        assert_eq!(limits.stdout_max_lines, Some(5));
        assert_eq!(limits.stderr_max_lines, Some(6));
        assert_eq!(limits.stdout_tail_lines, 1);
        assert_eq!(limits.stderr_tail_lines, 2);

        env::set_var(STDOUT_MAX_LINES_ENV, "9");
        env::set_var(STDERR_MAX_LINES_ENV, "0");
        let limits = resolve_output_limits(Some(&config)).unwrap();
        assert_eq!(limits.stdout_max_lines, Some(9));
        assert_eq!(limits.stderr_max_lines, Some(0));

        if let Some(prev) = prev_stdout {
            env::set_var(STDOUT_MAX_LINES_ENV, prev);
        } else {
            env::remove_var(STDOUT_MAX_LINES_ENV);
        }

        if let Some(prev) = prev_stderr {
            env::set_var(STDERR_MAX_LINES_ENV, prev);
        } else {
            env::remove_var(STDERR_MAX_LINES_ENV);
        }
    }

    #[test]
    fn resolve_timeout_prefers_explicit_then_env_then_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = env::var("BUILD_SERVICE_TIMEOUT").ok();

        env::remove_var("BUILD_SERVICE_TIMEOUT");
        let request = RequestConfig {
            timeout_sec: Some(12),
            env: HashMap::new(),
        };
        assert_eq!(resolve_timeout(None, Some(&request)).unwrap(), Some(12));
        assert_eq!(resolve_timeout(Some(5), Some(&request)).unwrap(), Some(5));

        env::set_var("BUILD_SERVICE_TIMEOUT", "9");
        assert_eq!(resolve_timeout(None, Some(&request)).unwrap(), Some(9));

        if let Some(prev) = prev {
            env::set_var("BUILD_SERVICE_TIMEOUT", prev);
        } else {
            env::remove_var("BUILD_SERVICE_TIMEOUT");
        }
    }
}
