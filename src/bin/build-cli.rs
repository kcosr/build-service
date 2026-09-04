use std::collections::{HashMap, VecDeque};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{ArgAction, Parser, Subcommand};
use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::Client;
use serde::Deserialize;
use tempfile::NamedTempFile;
use zip::write::FileOptions;
use zip::ZipWriter;

use build_service::protocol::{
    ArtifactArchive, ArtifactRestrictions, ArtifactSpec, Request, ResponseEvent, WorkspaceRequest,
    SCHEMA_VERSION,
};
use build_service::validation::{validate_relative_path, validate_relative_pattern};
use build_service::workspace::sanitize_workspace_id;

const DEFAULT_SOCKET_PATH: &str = "/run/build-service.sock";
const CLIENT_CONFIG_DIR: &str = ".build-service";
const CLIENT_CONFIG_FILE: &str = "config.toml";
const CONNECTION_FALLBACK_EXIT_CODE: u8 = 222;
const OUTPUT_PREFIX: &str = "[build-service]";
const ENABLED_ENV: &str = "BUILD_SERVICE_ENABLED";
const ENDPOINT_ENV: &str = "BUILD_SERVICE_ENDPOINT";
const TOKEN_ENV: &str = "BUILD_SERVICE_TOKEN";
const SOURCES_ENV: &str = "BUILD_SERVICE_SOURCES";
const SOURCES_EXCLUDE_ENV: &str = "BUILD_SERVICE_SOURCES_EXCLUDE";
const ARTIFACTS_ENV: &str = "BUILD_SERVICE_ARTIFACTS";
const ARTIFACTS_EXCLUDE_ENV: &str = "BUILD_SERVICE_ARTIFACTS_EXCLUDE";
const CWD_ENV: &str = "BUILD_SERVICE_CWD";
const TIMEOUT_ENV: &str = "BUILD_SERVICE_TIMEOUT";
const STDOUT_MAX_LINES_ENV: &str = "BUILD_SERVICE_STDOUT_MAX_LINES";
const STDERR_MAX_LINES_ENV: &str = "BUILD_SERVICE_STDERR_MAX_LINES";
const WORKSPACE_REUSE_ENV: &str = "BUILD_SERVICE_WORKSPACE_REUSE";
const WORKSPACE_ID_ENV: &str = "BUILD_SERVICE_WORKSPACE_ID";
const WORKSPACE_CREATE_ENV: &str = "BUILD_SERVICE_WORKSPACE_CREATE";
const WORKSPACE_REFRESH_ENV: &str = "BUILD_SERVICE_WORKSPACE_REFRESH";
const WORKSPACE_TTL_ENV: &str = "BUILD_SERVICE_WORKSPACE_TTL";

#[derive(Debug, Parser)]
#[command(author, version, about = "Client for the build-service daemon")]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Endpoint URL (http://, https://, or unix://)"
    )]
    endpoint: Option<String>,

    #[arg(long, global = true)]
    token: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Build(Box<BuildArgs>),
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum WorkspaceCommand {
    Reset(WorkspaceLifecycleArgs),
    Delete(WorkspaceLifecycleArgs),
}

#[derive(Debug, Parser)]
struct WorkspaceLifecycleArgs {
    #[arg(long)]
    workspace_id: Option<String>,
}

#[derive(Debug, Parser)]
struct BuildArgs {
    #[arg(long)]
    timeout: Option<u64>,

    #[arg(long = "source", action = ArgAction::Append)]
    source: Vec<String>,

    #[arg(long = "source-exclude", action = ArgAction::Append)]
    source_exclude: Vec<String>,

    #[arg(long = "artifact", action = ArgAction::Append)]
    artifact: Vec<String>,

    #[arg(long = "artifact-exclude", action = ArgAction::Append)]
    artifact_exclude: Vec<String>,

    #[arg(long)]
    cwd: Option<String>,

    #[arg(long = "env", action = ArgAction::Append)]
    request_env: Vec<String>,

    #[arg(long)]
    workspace_reuse: bool,

    #[arg(long)]
    workspace_id: Option<String>,

    #[arg(long)]
    request_id: Option<String>,

    #[arg(required = true)]
    command: String,

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct ClientConfig {
    #[serde(default)]
    sources: PatternConfig,
    #[serde(default)]
    artifacts: PatternConfig,
    #[serde(default)]
    request: Option<RequestConfig>,
    #[serde(default)]
    connection: Option<ConnectionConfig>,
    #[serde(default)]
    output: Option<OutputConfig>,
    #[serde(default)]
    workspace: Option<WorkspaceConfig>,
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
    cwd: Option<String>,
    #[serde(default)]
    env: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
struct ConnectionConfig {
    #[serde(default = "default_true")]
    enabled: bool,
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
    #[serde(default)]
    capture_logs: bool,
    #[serde(default)]
    log_dir: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct WorkspaceConfig {
    #[serde(default)]
    reuse: bool,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    create: bool,
    #[serde(default)]
    refresh: bool,
    #[serde(default)]
    ttl_sec: Option<u64>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone)]
enum Endpoint {
    Http { base: String },
    Unix { path: PathBuf },
}

#[derive(Debug)]
enum BuildError {
    ConnectionFailed(String),
    WorkspaceHttpStatus { status: u16, message: String },
    Other(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::ConnectionFailed(msg) | BuildError::Other(msg) => write!(f, "{msg}"),
            BuildError::WorkspaceHttpStatus { message, .. } => write!(f, "{message}"),
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

#[derive(Debug, Default, Clone)]
struct OutputLimits {
    stdout_max_lines: Option<usize>,
    stderr_max_lines: Option<usize>,
    stdout_tail_lines: usize,
    stderr_tail_lines: usize,
    capture_logs: bool,
    log_dir: Option<PathBuf>,
}

fn resolve_output_limits(
    config: Option<&OutputConfig>,
    run_dir: &Path,
) -> io::Result<OutputLimits> {
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
    let capture_logs = config.map(|config| config.capture_logs).unwrap_or(false);
    let log_dir = if capture_logs {
        Some(match config.and_then(|config| config.log_dir.as_deref()) {
            Some(raw) => resolve_log_dir(raw, run_dir)?,
            None => env::temp_dir().join("build-service"),
        })
    } else {
        None
    };

    Ok(OutputLimits {
        stdout_max_lines,
        stderr_max_lines,
        stdout_tail_lines,
        stderr_tail_lines,
        capture_logs,
        log_dir,
    })
}

fn resolve_log_dir(raw: &str, run_dir: &Path) -> io::Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output.log_dir must not be empty",
        ));
    }

    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(run_dir.join(path))
    }
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
    fn new(limits: &OutputLimits) -> Self {
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

    fn set_log_paths(&mut self, paths: &StreamLogPaths) {
        self.stdout.set_log_path(paths.stdout.clone());
        self.stderr.set_log_path(paths.stderr.clone());
    }

    fn clear_log_paths(&mut self) {
        self.stdout.clear_log_path();
        self.stderr.clear_log_path();
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

#[derive(Debug, Clone)]
enum BufferedStreamEvent {
    Stdout(String),
    Stderr(String),
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
    log_path: Option<PathBuf>,
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
            log_path: None,
        }
    }

    fn set_log_path(&mut self, path: PathBuf) {
        self.log_path = Some(path);
    }

    fn clear_log_path(&mut self) {
        self.log_path = None;
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
                    output.push_str(&self.suppression_notice());
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

    fn suppression_notice(&self) -> String {
        if let Some(log_path) = &self.log_path {
            format!(
                "{OUTPUT_PREFIX} suppressing {} output due to limits (full log: {})\n",
                self.label,
                log_path.display()
            )
        } else {
            format!(
                "{OUTPUT_PREFIX} suppressing {} output due to limits (increase output lines with {}=<lines>)\n",
                self.label,
                self.env_var
            )
        }
    }
}

#[derive(Debug, Clone)]
struct StreamLogPaths {
    stdout: PathBuf,
    stderr: PathBuf,
}

struct BuildLogSink {
    paths: StreamLogPaths,
    stdout_writer: BufWriter<Box<dyn Write>>,
    stderr_writer: BufWriter<Box<dyn Write>>,
}

impl BuildLogSink {
    fn new(base_dir: &Path, build_id: &str) -> io::Result<Self> {
        validate_build_id(build_id)?;

        let build_dir = base_dir.join(build_id);
        fs::create_dir_all(&build_dir)?;

        let stdout_path = build_dir.join("stdout.log");
        let stderr_path = build_dir.join("stderr.log");
        let stdout = BufWriter::new(Box::new(fs::File::create(&stdout_path)?) as Box<dyn Write>);
        let stderr = BufWriter::new(Box::new(fs::File::create(&stderr_path)?) as Box<dyn Write>);

        Ok(Self {
            paths: StreamLogPaths {
                stdout: stdout_path,
                stderr: stderr_path,
            },
            stdout_writer: stdout,
            stderr_writer: stderr,
        })
    }

    fn paths(&self) -> &StreamLogPaths {
        &self.paths
    }

    fn write_stdout(&mut self, data: &str) -> io::Result<()> {
        self.stdout_writer.write_all(data.as_bytes())?;
        self.stdout_writer.flush()
    }

    fn write_stderr(&mut self, data: &str) -> io::Result<()> {
        self.stderr_writer.write_all(data.as_bytes())?;
        self.stderr_writer.flush()
    }

    #[cfg(test)]
    fn from_writers(
        paths: StreamLogPaths,
        stdout_writer: Box<dyn Write>,
        stderr_writer: Box<dyn Write>,
    ) -> Self {
        Self {
            paths,
            stdout_writer: BufWriter::new(stdout_writer),
            stderr_writer: BufWriter::new(stderr_writer),
        }
    }
}

#[derive(Default)]
struct LogCaptureState {
    base_dir: Option<PathBuf>,
    sink: Option<BuildLogSink>,
    warning_emitted: bool,
    pending_events: VecDeque<BufferedStreamEvent>,
}

impl LogCaptureState {
    fn new(output_limits: &OutputLimits) -> Self {
        Self {
            base_dir: if output_limits.capture_logs {
                output_limits.log_dir.clone()
            } else {
                None
            },
            sink: None,
            warning_emitted: false,
            pending_events: VecDeque::new(),
        }
    }

    fn initialize(&mut self, build_id: &str) -> io::Result<Option<StreamLogPaths>> {
        let Some(base_dir) = self.base_dir.as_ref() else {
            return Ok(None);
        };

        if let Some(existing) = self.sink.as_ref() {
            return Ok(Some(existing.paths().clone()));
        }

        let sink = BuildLogSink::new(base_dir, build_id)?;
        let paths = sink.paths().clone();
        self.sink = Some(sink);
        Ok(Some(paths))
    }

    fn disable(&mut self) {
        self.base_dir = None;
        self.sink = None;
    }

    fn capture_requested(&self) -> bool {
        self.base_dir.is_some() || self.sink.is_some()
    }

    fn capture_active(&self) -> bool {
        self.sink.is_some()
    }

    fn push_pending(&mut self, event: BufferedStreamEvent) {
        self.pending_events.push_back(event);
    }

    fn drain_pending(&mut self, output: &mut OutputLimiter) -> io::Result<()> {
        while let Some(event) = self.pending_events.pop_front() {
            self.process_event(event, output)?;
        }
        Ok(())
    }

    fn flush_pending_to_terminal(&mut self, output: &mut OutputLimiter) -> io::Result<()> {
        while let Some(event) = self.pending_events.pop_front() {
            write_event_to_terminal(event, output)?;
        }
        Ok(())
    }

    fn process_event(
        &mut self,
        event: BufferedStreamEvent,
        output: &mut OutputLimiter,
    ) -> io::Result<()> {
        if let Some(sink) = self.sink.as_mut() {
            let log_result = match &event {
                BufferedStreamEvent::Stdout(data) => sink.write_stdout(data),
                BufferedStreamEvent::Stderr(data) => sink.write_stderr(data),
            };

            if let Err(err) = log_result {
                output.clear_log_paths();
                self.disable();
                self.write_warning(&err.to_string())?;
            }
        }

        write_event_to_terminal(event, output)
    }

    fn completion_paths(&self) -> Option<&StreamLogPaths> {
        self.sink.as_ref().map(|sink| sink.paths())
    }

    fn write_warning(&mut self, message: &str) -> io::Result<()> {
        if self.warning_emitted {
            return Ok(());
        }

        self.warning_emitted = true;
        let mut stderr = io::stderr();
        writeln!(stderr, "{OUTPUT_PREFIX} log capture unavailable: {message}")?;
        stderr.flush()
    }

    fn write_completion_notice(&self) -> io::Result<()> {
        let Some(paths) = self.completion_paths() else {
            return Ok(());
        };

        let mut stderr = io::stderr();
        writeln!(
            stderr,
            "{OUTPUT_PREFIX} saved full logs: stdout={}, stderr={}",
            paths.stdout.display(),
            paths.stderr.display()
        )?;
        stderr.flush()
    }
}

fn write_event_to_terminal(
    event: BufferedStreamEvent,
    output: &mut OutputLimiter,
) -> io::Result<()> {
    match event {
        BufferedStreamEvent::Stdout(data) => output.write_stdout(&data),
        BufferedStreamEvent::Stderr(data) => output.write_stderr(&data),
    }
}

fn validate_build_id(build_id: &str) -> io::Result<()> {
    let trimmed = build_id.trim();
    if trimmed.is_empty() || matches!(trimmed, "." | "..") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "build id must be a non-empty single path component",
        ));
    }

    if trimmed.contains('\0') || trimmed.contains('/') || trimmed.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "build id must not contain path separators or NUL bytes",
        ));
    }

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let run_dir = match env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("failed to resolve current directory: {err}");
            return ExitCode::from(1);
        }
    };

    let config_path = find_client_config_path(&run_dir);
    let repo_root = config_path
        .as_ref()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| run_dir.clone());
    let client_config = match load_client_config(config_path.as_deref()) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let config_loaded = config_path.is_some();

    let connection = client_config.connection.as_ref();
    if !resolve_connection_enabled(connection) {
        eprintln!("{OUTPUT_PREFIX} disabled (BUILD_SERVICE_ENABLED/connection.enabled)");
        return ExitCode::from(CONNECTION_FALLBACK_EXIT_CODE);
    }

    match cli.command {
        Commands::Build(args) => run_build_command(
            *args,
            cli.endpoint,
            cli.token,
            run_dir,
            repo_root,
            client_config,
            config_loaded,
        ),
        Commands::Workspace { command } => run_workspace_command(
            command,
            cli.endpoint,
            cli.token,
            run_dir,
            repo_root,
            client_config,
            config_loaded,
        ),
    }
}

fn run_build_command(
    args: BuildArgs,
    endpoint_arg: Option<String>,
    token_arg: Option<String>,
    run_dir: PathBuf,
    repo_root: PathBuf,
    client_config: ClientConfig,
    config_loaded: bool,
) -> ExitCode {
    let connection = client_config.connection.as_ref();

    let source_patterns = match resolve_patterns(
        &client_config.sources,
        SOURCES_ENV,
        &args.source,
        SOURCES_EXCLUDE_ENV,
        &args.source_exclude,
    ) {
        Ok(patterns) => patterns,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let artifact_patterns = match resolve_patterns(
        &client_config.artifacts,
        ARTIFACTS_ENV,
        &args.artifact,
        ARTIFACTS_EXCLUDE_ENV,
        &args.artifact_exclude,
    ) {
        Ok(patterns) => patterns,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    if let Err(err) = validate_patterns(&source_patterns, "sources") {
        eprintln!("{err}");
        return ExitCode::from(1);
    }
    if let Err(err) = validate_patterns(&artifact_patterns, "artifacts") {
        eprintln!("{err}");
        return ExitCode::from(1);
    }

    let source_archive = match build_source_archive(&repo_root, &source_patterns) {
        Ok(archive) => archive,
        Err(err) => {
            eprintln!("failed to package sources: {err}");
            return ExitCode::from(1);
        }
    };

    let cwd = match resolve_request_cwd(
        args.cwd,
        client_config.request.as_ref(),
        &repo_root,
        &run_dir,
    ) {
        Ok(cwd) => cwd,
        Err(err) => {
            eprintln!("failed to resolve cwd: {err}");
            return ExitCode::from(1);
        }
    };

    let artifacts = ArtifactSpec {
        include: artifact_patterns.include,
        exclude: artifact_patterns.exclude,
    };

    let env = match resolve_request_env(client_config.request.as_ref(), &args.request_env) {
        Ok(env) => env,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    let timeout_sec = match resolve_timeout(args.timeout, client_config.request.as_ref()) {
        Ok(timeout) => timeout,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    let workspace = match resolve_workspace_config(
        args.workspace_reuse,
        args.workspace_id,
        client_config.workspace.as_ref(),
        &repo_root,
    ) {
        Ok(workspace) => workspace,
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
        workspace,
    };

    let endpoint = match resolve_endpoint(endpoint_arg, connection, config_loaded) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let token = resolve_token(token_arg, connection);
    let output_limits = match resolve_output_limits(client_config.output.as_ref(), &run_dir) {
        Ok(limits) => limits,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    let build = match run_build(
        &request,
        source_archive.as_ref(),
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
            BuildError::Other(msg) | BuildError::WorkspaceHttpStatus { message: msg, .. } => {
                eprintln!("build request failed: {msg}");
                return ExitCode::from(1);
            }
        },
    };

    if let Some(workspace_id) = &build.workspace_id {
        if let Err(err) = write_workspace_id_file(&repo_root, workspace_id) {
            eprintln!("failed to write workspace-id: {err}");
        }
    }

    if let Some(restrictions) = &build.artifact_restrictions {
        if let Err(err) = write_artifact_restrictions_notice(restrictions) {
            eprintln!("failed to report artifact restrictions: {err}");
            return ExitCode::from(1);
        }
    }

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

fn find_client_config_path(start_dir: &Path) -> Option<PathBuf> {
    let mut dir = start_dir.to_path_buf();
    loop {
        let candidate = dir.join(CLIENT_CONFIG_DIR).join(CLIENT_CONFIG_FILE);
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }

    None
}

fn load_client_config(path: Option<&Path>) -> io::Result<ClientConfig> {
    let Some(path) = path else {
        return Ok(ClientConfig::default());
    };

    let raw = fs::read_to_string(path)?;
    toml::from_str(&raw).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn resolve_patterns(
    config: &PatternConfig,
    include_env: &str,
    include_args: &[String],
    exclude_env: &str,
    exclude_args: &[String],
) -> io::Result<PatternConfig> {
    Ok(PatternConfig {
        include: merge_pattern_values(&config.include, include_env, include_args)?,
        exclude: merge_pattern_values(&config.exclude, exclude_env, exclude_args)?,
    })
}

fn merge_pattern_values(
    config_values: &[String],
    env_name: &str,
    cli_values: &[String],
) -> io::Result<Vec<String>> {
    let mut values = config_values.to_vec();
    values.extend(parse_csv_env_values(env_name)?);
    values.extend(
        cli_values
            .iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    );
    Ok(values)
}

fn parse_csv_env_values(name: &str) -> io::Result<Vec<String>> {
    let raw = match env::var(name) {
        Ok(raw) => raw,
        Err(_) => return Ok(Vec::new()),
    };

    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect())
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

fn resolve_relative_cwd(root: &Path, cwd: &Path) -> io::Result<Option<String>> {
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

fn resolve_request_cwd(
    explicit: Option<String>,
    request: Option<&RequestConfig>,
    repo_root: &Path,
    run_dir: &Path,
) -> io::Result<Option<String>> {
    if let Some(value) = explicit {
        return normalize_request_cwd(&value);
    }

    if let Ok(value) = env::var(CWD_ENV) {
        if !value.trim().is_empty() {
            return normalize_request_cwd(&value);
        }
    }

    if let Some(value) = request.and_then(|request| request.cwd.as_deref()) {
        if !value.trim().is_empty() {
            return normalize_request_cwd(value);
        }
    }

    resolve_relative_cwd(repo_root, run_dir)
}

fn normalize_request_cwd(value: &str) -> io::Result<Option<String>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    validate_relative_path(trimmed, "cwd")
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    Ok(Some(trimmed.to_string()))
}

fn resolve_request_env(
    request: Option<&RequestConfig>,
    cli_entries: &[String],
) -> io::Result<Option<HashMap<String, String>>> {
    let mut env_map = request
        .map(|request| request.env.clone())
        .unwrap_or_default();
    for entry in cli_entries {
        let (key, value) = parse_request_env_entry(entry)?;
        env_map.insert(key, value);
    }

    if env_map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(env_map))
    }
}

fn parse_request_env_entry(entry: &str) -> io::Result<(String, String)> {
    let (key, value) = entry.split_once('=').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid --env value {entry:?}, expected KEY=VALUE"),
        )
    })?;

    if key.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid --env value {entry:?}, key must not be empty"),
        ));
    }

    Ok((key.trim().to_string(), value.to_string()))
}

fn build_source_archive(
    root: &Path,
    patterns: &PatternConfig,
) -> io::Result<Option<NamedTempFile>> {
    if patterns.include.is_empty() {
        return Ok(None);
    }

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
    Ok(Some(temp))
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
    config_loaded: bool,
) -> io::Result<Endpoint> {
    if let Some(endpoint) = explicit {
        if !endpoint.trim().is_empty() {
            return parse_endpoint(&endpoint);
        }
    }

    if let Ok(env_endpoint) = env::var(ENDPOINT_ENV) {
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

    if config_loaded {
        let default_endpoint = format!("unix://{DEFAULT_SOCKET_PATH}");
        return parse_endpoint(&default_endpoint);
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "endpoint must be provided via --endpoint, BUILD_SERVICE_ENDPOINT, or client config",
    ))
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

    if let Ok(env_timeout) = env::var(TIMEOUT_ENV) {
        let trimmed = env_timeout.trim();
        if !trimmed.is_empty() {
            let parsed: u64 = trimmed.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{TIMEOUT_ENV} must be a positive integer, got {trimmed}"),
                )
            })?;
            if parsed == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{TIMEOUT_ENV} must be greater than zero"),
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

    if let Ok(env_token) = env::var(TOKEN_ENV) {
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

fn resolve_connection_enabled(config: Option<&ConnectionConfig>) -> bool {
    if let Ok(raw) = env::var(ENABLED_ENV) {
        let trimmed = raw.trim();
        let lower = trimmed.to_ascii_lowercase();
        let disabled = matches!(lower.as_str(), "" | "0" | "false" | "no" | "off");
        return !disabled;
    }

    config.map(|connection| connection.enabled).unwrap_or(true)
}

fn parse_env_bool(name: &str) -> io::Result<Option<bool>> {
    let value = match env::var(name) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be true or false"),
        ));
    }

    match trimmed.to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(Some(true)),
        "false" | "0" => Ok(Some(false)),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be true or false"),
        )),
    }
}

fn parse_env_u64(name: &str) -> io::Result<Option<u64>> {
    let value = match env::var(name) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a non-negative integer"),
        ));
    }

    let parsed: u64 = trimmed.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be a non-negative integer, got {trimmed}"),
        )
    })?;
    Ok(Some(parsed))
}

fn get_repo_name(repo_root: &Path) -> io::Result<String> {
    let repo_name = repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .ok_or_else(|| io::Error::other("failed to resolve repo name from repo root"))?;

    Ok(repo_name.to_string())
}

fn get_git_branch(repo_root: &Path) -> io::Result<String> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("--abbrev-ref")
        .arg("HEAD")
        .current_dir(repo_root)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = if stderr.trim().is_empty() {
            "failed to resolve git branch".to_string()
        } else {
            format!("failed to resolve git branch: {}", stderr.trim())
        };
        return Err(io::Error::other(message));
    }

    let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if branch.is_empty() {
        return Err(io::Error::other(
            "failed to resolve git branch: empty output",
        ));
    }

    if branch == "HEAD" {
        Ok("detached".to_string())
    } else {
        Ok(branch)
    }
}

fn expand_workspace_macros(id: &str, repo_root: &Path) -> io::Result<String> {
    let mut expanded = id.to_string();

    if expanded.contains("{uid}") {
        // SAFETY: `geteuid` has no preconditions and reads process metadata only.
        let uid = unsafe { libc::geteuid() };
        expanded = expanded.replace("{uid}", &uid.to_string());
    }

    if expanded.contains("{branch}") {
        let branch = get_git_branch(repo_root)?;
        expanded = expanded.replace("{branch}", branch.as_str());
    }

    if expanded.contains("{repo}") {
        let repo_name = get_repo_name(repo_root)?;
        expanded = expanded.replace("{repo}", repo_name.as_str());
    }

    Ok(expanded)
}

fn resolve_workspace_config(
    cli_reuse: bool,
    cli_id: Option<String>,
    config: Option<&WorkspaceConfig>,
    repo_root: &Path,
) -> io::Result<Option<WorkspaceRequest>> {
    let reuse = if cli_reuse {
        true
    } else if let Some(value) = parse_env_bool(WORKSPACE_REUSE_ENV)? {
        value
    } else {
        config.map(|cfg| cfg.reuse).unwrap_or(false)
    };

    if !reuse {
        if cli_id
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--workspace-id requires --workspace-reuse",
            ));
        }
        return Ok(None);
    }

    let cli_id = cli_id.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });
    let env_id = env::var(WORKSPACE_ID_ENV).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });
    let config_id = config.and_then(|cfg| cfg.id.as_ref().map(|id| id.trim().to_string()));
    let mut id = cli_id.or(env_id).or(config_id);
    if let Some(ref raw_id) = id {
        id = Some(expand_workspace_macros(raw_id, repo_root)?);
    }

    let create = if let Some(value) = parse_env_bool(WORKSPACE_CREATE_ENV)? {
        value
    } else {
        config.map(|cfg| cfg.create).unwrap_or(false)
    };

    let refresh = if let Some(value) = parse_env_bool(WORKSPACE_REFRESH_ENV)? {
        value
    } else {
        config.map(|cfg| cfg.refresh).unwrap_or(false)
    };

    let ttl_sec = if let Some(value) = parse_env_u64(WORKSPACE_TTL_ENV)? {
        Some(value)
    } else {
        config.and_then(|cfg| cfg.ttl_sec)
    };

    if id.is_none() {
        id = read_workspace_id_file(repo_root)?;
    }

    if create && id.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace.create requires workspace.id",
        ));
    }

    Ok(Some(WorkspaceRequest {
        reuse,
        id,
        create: if create { Some(true) } else { None },
        refresh: if refresh { Some(true) } else { None },
        ttl_sec,
    }))
}

fn read_workspace_id_file(repo_root: &Path) -> io::Result<Option<String>> {
    let path = repo_root.join(CLIENT_CONFIG_DIR).join("workspace-id");
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace-id file is empty",
        ));
    }

    Ok(Some(trimmed.to_string()))
}

fn write_workspace_id_file(repo_root: &Path, workspace_id: &str) -> io::Result<()> {
    let dir = repo_root.join(CLIENT_CONFIG_DIR);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("workspace-id"), format!("{workspace_id}\n"))?;
    Ok(())
}

fn remove_workspace_id_file(repo_root: &Path) -> io::Result<()> {
    let path = repo_root.join(CLIENT_CONFIG_DIR).join("workspace-id");
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

struct BuildResult {
    exit_code: i32,
    timed_out: bool,
    artifacts: Option<ArtifactArchive>,
    artifact_restrictions: Option<ArtifactRestrictions>,
    workspace_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WorkspaceLifecycleResponse {
    workspace_id: String,
    status: String,
}

#[derive(Debug, Clone, Copy)]
enum WorkspaceLifecycleAction {
    Reset,
    Delete,
}

impl WorkspaceLifecycleAction {
    fn status(self) -> &'static str {
        match self {
            WorkspaceLifecycleAction::Reset => "reset",
            WorkspaceLifecycleAction::Delete => "deleted",
        }
    }

    fn path(self, workspace_id: &str) -> String {
        match self {
            WorkspaceLifecycleAction::Reset => {
                format!("/v1/workspaces/{workspace_id}/reset")
            }
            WorkspaceLifecycleAction::Delete => format!("/v1/workspaces/{workspace_id}"),
        }
    }
}

fn run_workspace_command(
    command: WorkspaceCommand,
    endpoint_arg: Option<String>,
    token_arg: Option<String>,
    _run_dir: PathBuf,
    repo_root: PathBuf,
    client_config: ClientConfig,
    config_loaded: bool,
) -> ExitCode {
    let connection = client_config.connection.as_ref();
    let (action, args) = match command {
        WorkspaceCommand::Reset(args) => (WorkspaceLifecycleAction::Reset, args),
        WorkspaceCommand::Delete(args) => (WorkspaceLifecycleAction::Delete, args),
    };

    let workspace_id = match resolve_lifecycle_workspace_id(
        args.workspace_id,
        client_config.workspace.as_ref(),
        &repo_root,
    ) {
        Ok(workspace_id) => workspace_id,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    let endpoint = match resolve_endpoint(endpoint_arg, connection, config_loaded) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let token = resolve_token(token_arg, connection);

    match run_workspace_lifecycle(action, &workspace_id, &endpoint, token.as_deref()) {
        Ok(response) => {
            println!(
                "{OUTPUT_PREFIX} workspace {} {}",
                response.workspace_id, response.status
            );
            if matches!(action, WorkspaceLifecycleAction::Delete) {
                if let Err(err) = remove_workspace_id_file(&repo_root) {
                    eprintln!("failed to remove workspace-id: {err}");
                    return ExitCode::from(1);
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("workspace request failed: {err}");
            match err {
                BuildError::WorkspaceHttpStatus { status: 409, .. } => ExitCode::from(2),
                BuildError::WorkspaceHttpStatus { status: 404, .. } => ExitCode::from(3),
                _ => ExitCode::from(1),
            }
        }
    }
}

fn resolve_lifecycle_workspace_id(
    cli_id: Option<String>,
    config: Option<&WorkspaceConfig>,
    repo_root: &Path,
) -> io::Result<String> {
    let cli_id = cli_id.and_then(non_empty_trimmed);
    let env_id = env::var(WORKSPACE_ID_ENV).ok().and_then(non_empty_trimmed);
    let config_id =
        config.and_then(|cfg| cfg.id.as_ref().and_then(|id| non_empty_trimmed(id.clone())));
    let mut id = cli_id.or(env_id).or(config_id);
    if let Some(ref raw_id) = id {
        id = Some(expand_workspace_macros(raw_id, repo_root)?);
    }
    if id.is_none() {
        id = read_workspace_id_file(repo_root)?;
    }

    let id = id.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace id required for workspace command",
        )
    })?;
    let sanitized = sanitize_workspace_id(&id);
    if sanitized.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "workspace id must match [A-Za-z0-9_-]+",
        ));
    }
    Ok(sanitized)
}

fn non_empty_trimmed(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn run_workspace_lifecycle(
    action: WorkspaceLifecycleAction,
    workspace_id: &str,
    endpoint: &Endpoint,
    token: Option<&str>,
) -> Result<WorkspaceLifecycleResponse, BuildError> {
    let path = action.path(workspace_id);
    let (client, url, send_auth) = match endpoint {
        Endpoint::Http { base } => (
            Client::builder()
                .build()
                .map_err(|err| BuildError::Other(format!("failed to create client: {err}")))?,
            format!("{base}{path}"),
            true,
        ),
        Endpoint::Unix { path: socket } => {
            let client = Client::builder()
                .unix_socket(socket.clone())
                .build()
                .map_err(|err| BuildError::Other(format!("failed to create client: {err}")))?;
            (client, format!("http://localhost{path}"), false)
        }
    };

    let mut builder = match action {
        WorkspaceLifecycleAction::Reset => client.post(url),
        WorkspaceLifecycleAction::Delete => client.delete(url),
    };
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
        return Err(BuildError::WorkspaceHttpStatus {
            status: status.as_u16(),
            message: format!("server returned {status}: {body}"),
        });
    }

    let lifecycle: WorkspaceLifecycleResponse = response
        .json()
        .map_err(|err| BuildError::Other(format!("invalid response format: {err}")))?;
    if lifecycle.status != action.status() {
        return Err(BuildError::Other(format!(
            "unexpected workspace status {}, expected {}; workspace may have been mutated, check server state",
            lifecycle.status,
            action.status()
        )));
    }
    Ok(lifecycle)
}

fn run_build(
    request: &Request,
    source_archive: Option<&NamedTempFile>,
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
    let mut form = Form::new().part(
        "metadata",
        Part::text(metadata).mime_str("application/json").unwrap(),
    );
    if let Some(source_archive) = source_archive {
        let source_part = Part::file(source_archive.path())
            .map_err(|err| BuildError::Other(format!("failed to read source archive: {err}")))?;
        form = form.part("source", source_part.mime_str("application/zip").unwrap());
    }

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
    let mut artifact_restrictions: Option<ArtifactRestrictions> = None;
    let mut workspace_id: Option<String> = None;
    let mut output = OutputLimiter::new(output_limits);
    let mut log_capture = LogCaptureState::new(output_limits);
    let mut build_event_seen = false;

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
                if log_capture.capture_requested() && !log_capture.capture_active() {
                    log_capture.push_pending(BufferedStreamEvent::Stdout(data));
                } else {
                    log_capture
                        .process_event(BufferedStreamEvent::Stdout(data), &mut output)
                        .map_err(|err| {
                            BuildError::Other(format!("failed to write stdout: {err}"))
                        })?;
                }
            }
            ResponseEvent::Stderr { data } => {
                if log_capture.capture_requested() && !log_capture.capture_active() {
                    log_capture.push_pending(BufferedStreamEvent::Stderr(data));
                } else {
                    log_capture
                        .process_event(BufferedStreamEvent::Stderr(data), &mut output)
                        .map_err(|err| {
                            BuildError::Other(format!("failed to write stderr: {err}"))
                        })?;
                }
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
                artifact_restrictions: event_artifact_restrictions,
                workspace_id: event_workspace_id,
            } => {
                exit_code = Some(code);
                timed_out = timed;
                artifacts = event_artifacts;
                artifact_restrictions = event_artifact_restrictions;
                workspace_id = event_workspace_id;
                break;
            }
            ResponseEvent::Build { id, .. } => {
                build_event_seen = true;
                match log_capture.initialize(&id) {
                    Ok(Some(paths)) => {
                        output.set_log_paths(&paths);
                        log_capture.drain_pending(&mut output).map_err(|err| {
                            BuildError::Other(format!("failed to write buffered output: {err}"))
                        })?;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        output.clear_log_paths();
                        log_capture.disable();
                        log_capture
                            .write_warning(&err.to_string())
                            .map_err(|warn_err| {
                                BuildError::Other(format!(
                                    "failed to report log capture warning: {warn_err}"
                                ))
                            })?;
                        log_capture.flush_pending_to_terminal(&mut output).map_err(
                            |flush_err| {
                                BuildError::Other(format!(
                                    "failed to write buffered output: {flush_err}"
                                ))
                            },
                        )?;
                    }
                }
            }
        }
    }

    if log_capture.capture_requested() && !build_event_seen {
        output.clear_log_paths();
        log_capture.disable();
        log_capture
            .write_warning("build id was not received from the response stream")
            .map_err(|err| {
                BuildError::Other(format!("failed to report log capture warning: {err}"))
            })?;
        log_capture
            .flush_pending_to_terminal(&mut output)
            .map_err(|err| BuildError::Other(format!("failed to write buffered output: {err}")))?;
    }

    output
        .finish()
        .map_err(|err| BuildError::Other(format!("failed to flush output: {err}")))?;

    log_capture.write_completion_notice().map_err(|err| {
        BuildError::Other(format!("failed to write log completion notice: {err}"))
    })?;

    match exit_code {
        Some(code) => Ok(BuildResult {
            exit_code: code,
            timed_out,
            artifacts,
            artifact_restrictions,
            workspace_id,
        }),
        None => Err(BuildError::Other("missing exit event".to_string())),
    }
}

fn write_artifact_restrictions_notice(restrictions: &ArtifactRestrictions) -> io::Result<()> {
    let mut stderr = io::stderr();
    writeln!(stderr, "{}", artifact_restrictions_notice(restrictions))
}

fn artifact_restrictions_notice(restrictions: &ArtifactRestrictions) -> String {
    let file_label = if restrictions.omitted_count == 1 {
        "file was"
    } else {
        "files were"
    };
    if restrictions.matched_patterns.is_empty() {
        format!(
            "{OUTPUT_PREFIX} {} requested artifact {file_label} omitted by server artifact restrictions",
            restrictions.omitted_count
        )
    } else {
        format!(
            "{OUTPUT_PREFIX} {} requested artifact {file_label} omitted by server artifact restrictions: {}",
            restrictions.omitted_count,
            restrictions.matched_patterns.join(", ")
        )
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
        validate_zip_entry_path(file.name())?;
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

fn validate_zip_entry_path(name: &str) -> io::Result<()> {
    if name.contains('\\') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zip entry had invalid path",
        ));
    }

    let path = Path::new(name);
    if path.components().any(|component| {
        matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::ParentDir
        )
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zip entry had invalid path",
        ));
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
    use std::io::{BufRead, BufReader, Read};
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;
    use zip::ZipArchive;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn git_available() -> bool {
        Command::new("git").arg("--version").output().is_ok()
    }

    fn run_git(repo_root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(repo_root)
            .output()
            .expect("run git");
        if !output.status.success() {
            panic!(
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn init_git_repo(repo_root: &Path) {
        run_git(repo_root, &["init"]);
        run_git(repo_root, &["config", "user.email", "test@example.com"]);
        run_git(repo_root, &["config", "user.name", "Test"]);
        fs::write(repo_root.join("README.md"), "test").expect("write readme");
        run_git(repo_root, &["add", "."]);
        run_git(repo_root, &["commit", "-m", "init"]);
    }

    fn create_test_zip(name: &str, contents: &[u8]) -> io::Result<NamedTempFile> {
        let temp = NamedTempFile::new()?;
        let file = temp.reopen()?;
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file(name, options).map_err(io::Error::other)?;
        zip.write_all(contents)?;
        zip.finish().map_err(io::Error::other)?;
        Ok(temp)
    }

    #[test]
    fn artifact_restrictions_notice_lists_patterns_without_paths() {
        let restrictions = ArtifactRestrictions {
            omitted_count: 2,
            matched_patterns: vec!["**/*.cpp".to_string(), "**/*.h".to_string()],
        };

        assert_eq!(
            artifact_restrictions_notice(&restrictions),
            "[build-service] 2 requested artifact files were omitted by server artifact restrictions: **/*.cpp, **/*.h"
        );
    }

    fn start_ndjson_server(body: String) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
        let addr = listener.local_addr().expect("server addr");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut request_line = String::new();
            reader
                .read_line(&mut request_line)
                .expect("read request line");
            assert!(
                request_line.starts_with("GET ") || request_line.starts_with("POST "),
                "unexpected request line: {request_line:?}"
            );

            let mut content_length = None;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("read header line");
                if line == "\r\n" || line.is_empty() {
                    break;
                }

                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length =
                            Some(value.trim().parse::<usize>().expect("parse content length"));
                    }
                }
            }

            if let Some(content_length) = content_length {
                let mut discard = vec![0; content_length];
                reader.read_exact(&mut discard).expect("read request body");
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            stream.flush().expect("flush response");
        });

        (format!("http://{addr}"), handle)
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("simulated write failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

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

        let archive = build_source_archive(root, &patterns)
            .expect("archive")
            .expect("source archive");
        let file = fs::File::open(archive.path()).expect("open zip");
        let archive = ZipArchive::new(file).expect("read zip");
        assert!(!archive.is_empty(), "archive should have entries");
    }

    #[test]
    fn build_source_archive_anchors_target_exclusion_to_repo_root() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path();
        fs::create_dir_all(root.join("target/debug")).expect("create cargo target dir");
        fs::create_dir_all(root.join("src/config/target")).expect("create nested target dir");
        fs::write(root.join("target/debug/output"), "generated").expect("write build output");
        fs::write(root.join("src/config/target/local.rs"), "source").expect("write source");

        let patterns = PatternConfig {
            include: vec!["**".to_string()],
            exclude: vec!["target/**".to_string()],
        };

        let archive = build_source_archive(root, &patterns)
            .expect("archive")
            .expect("source archive");
        let file = fs::File::open(archive.path()).expect("open zip");
        let archive = ZipArchive::new(file).expect("read zip");
        let names = archive.file_names().collect::<Vec<_>>();

        assert!(names.contains(&"src/config/target/local.rs"));
        assert!(!names.contains(&"target/debug/output"));
    }

    #[test]
    fn build_source_archive_returns_none_when_sources_are_empty() {
        let temp = tempdir().expect("tempdir");
        let archive =
            build_source_archive(temp.path(), &PatternConfig::default()).expect("archive");
        assert!(archive.is_none());
    }

    #[test]
    fn extract_zip_rejects_parent_dir_internal_bypass() {
        let temp = tempdir().expect("tempdir");
        let archive = create_test_zip("foo/../.build-service/manifest.json", b"bad").expect("zip");

        let err = extract_zip(archive.path(), temp.path()).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!temp.path().join(".build-service/manifest.json").exists());
    }

    #[test]
    fn extract_zip_rejects_backslash_paths() {
        let temp = tempdir().expect("tempdir");
        let archive = create_test_zip("..\\.build-service\\manifest.json", b"bad").expect("zip");

        let err = extract_zip(archive.path(), temp.path()).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn remove_workspace_id_file_deletes_cached_id() {
        let temp = tempdir().expect("tempdir");
        write_workspace_id_file(temp.path(), "custom").expect("write id");

        remove_workspace_id_file(temp.path()).expect("remove id");
        remove_workspace_id_file(temp.path()).expect("remove missing id");

        assert!(read_workspace_id_file(temp.path())
            .expect("read id")
            .is_none());
    }

    #[test]
    fn resolve_patterns_appends_config_env_and_cli_values() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = env::var(SOURCES_ENV).ok();
        let prev_exclude = env::var(SOURCES_EXCLUDE_ENV).ok();
        env::set_var(SOURCES_ENV, "env-a, env-b");
        env::set_var(SOURCES_EXCLUDE_ENV, "env-ignore");

        let config = PatternConfig {
            include: vec!["config-a".to_string()],
            exclude: vec!["config-ignore".to_string()],
        };
        let merged = resolve_patterns(
            &config,
            SOURCES_ENV,
            &["cli-a".to_string()],
            SOURCES_EXCLUDE_ENV,
            &["cli-ignore".to_string()],
        )
        .expect("patterns");

        assert_eq!(merged.include, vec!["config-a", "env-a", "env-b", "cli-a"]);
        assert_eq!(
            merged.exclude,
            vec!["config-ignore", "env-ignore", "cli-ignore"]
        );

        if let Some(prev) = prev {
            env::set_var(SOURCES_ENV, prev);
        } else {
            env::remove_var(SOURCES_ENV);
        }
        if let Some(prev) = prev_exclude {
            env::set_var(SOURCES_EXCLUDE_ENV, prev);
        } else {
            env::remove_var(SOURCES_EXCLUDE_ENV);
        }
    }

    #[test]
    fn resolve_endpoint_requires_explicit_source_without_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = env::var(ENDPOINT_ENV).ok();
        env::remove_var(ENDPOINT_ENV);

        let err = resolve_endpoint(None, None, false).unwrap_err();
        assert!(
            err.to_string().contains("BUILD_SERVICE_ENDPOINT"),
            "unexpected error: {err}"
        );

        if let Some(prev) = prev {
            env::set_var(ENDPOINT_ENV, prev);
        }
    }

    #[test]
    fn resolve_endpoint_uses_default_socket_when_config_is_present() {
        let endpoint = resolve_endpoint(None, None, true).expect("endpoint");
        match endpoint {
            Endpoint::Unix { path } => assert_eq!(path, PathBuf::from(DEFAULT_SOCKET_PATH)),
            Endpoint::Http { .. } => panic!("expected unix endpoint"),
        }
    }

    #[test]
    fn resolve_request_env_merges_config_and_cli_values() {
        let request = RequestConfig {
            timeout_sec: None,
            cwd: None,
            env: HashMap::from([("CC".to_string(), "clang".to_string())]),
        };
        let resolved =
            resolve_request_env(Some(&request), &["VERBOSE=1".to_string()]).expect("env");
        let env_map = resolved.expect("request env");
        assert_eq!(env_map.get("CC").map(String::as_str), Some("clang"));
        assert_eq!(env_map.get("VERBOSE").map(String::as_str), Some("1"));
    }

    #[test]
    fn parse_request_env_entry_preserves_equals_in_values() {
        let (key, value) = parse_request_env_entry("TOKEN=abc=def").expect("env entry");
        assert_eq!(key, "TOKEN");
        assert_eq!(value, "abc=def");
    }

    #[test]
    fn resolve_request_cwd_prefers_explicit_then_env_then_config_then_relative() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = env::var(CWD_ENV).ok();
        let temp = tempdir().expect("tempdir");
        let repo_root = temp.path().join("repo");
        let nested = repo_root.join("nested");
        fs::create_dir_all(&nested).expect("nested dir");

        let request = RequestConfig {
            timeout_sec: None,
            cwd: Some("from-config".to_string()),
            env: HashMap::new(),
        };

        env::remove_var(CWD_ENV);
        assert_eq!(
            resolve_request_cwd(
                Some("from-cli".to_string()),
                Some(&request),
                &repo_root,
                &nested
            )
            .expect("cwd"),
            Some("from-cli".to_string())
        );

        env::set_var(CWD_ENV, "from-env");
        assert_eq!(
            resolve_request_cwd(None, Some(&request), &repo_root, &nested).expect("cwd"),
            Some("from-env".to_string())
        );

        env::remove_var(CWD_ENV);
        assert_eq!(
            resolve_request_cwd(None, Some(&request), &repo_root, &nested).expect("cwd"),
            Some("from-config".to_string())
        );

        assert_eq!(
            resolve_request_cwd(None, None, &repo_root, &nested).expect("cwd"),
            Some("nested".to_string())
        );

        if let Some(prev) = prev {
            env::set_var(CWD_ENV, prev);
        } else {
            env::remove_var(CWD_ENV);
        }
    }

    #[test]
    fn resolve_workspace_config_rejects_cli_id_without_reuse() {
        let temp = tempdir().expect("tempdir");
        let err = resolve_workspace_config(false, Some("ws-id".to_string()), None, temp.path())
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("--workspace-id requires --workspace-reuse"),
            "unexpected error: {err}"
        );
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
            capture_logs: false,
            log_dir: None,
        };

        let temp = tempdir().expect("tempdir");
        let limits = resolve_output_limits(Some(&config), temp.path()).unwrap();
        assert_eq!(limits.stdout_max_lines, Some(5));
        assert_eq!(limits.stderr_max_lines, Some(6));
        assert_eq!(limits.stdout_tail_lines, 1);
        assert_eq!(limits.stderr_tail_lines, 2);
        assert!(!limits.capture_logs);
        assert_eq!(limits.log_dir, None);

        env::set_var(STDOUT_MAX_LINES_ENV, "9");
        env::set_var(STDERR_MAX_LINES_ENV, "0");
        let limits = resolve_output_limits(Some(&config), temp.path()).unwrap();
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
    fn resolve_output_limits_enables_capture_and_resolves_log_dir() {
        let temp = tempdir().expect("tempdir");
        let config = OutputConfig {
            stdout_max_lines: None,
            stderr_max_lines: None,
            stdout_tail_lines: 0,
            stderr_tail_lines: 0,
            capture_logs: true,
            log_dir: Some("captured-logs".to_string()),
        };

        let limits = resolve_output_limits(Some(&config), temp.path()).expect("resolve limits");
        assert!(limits.capture_logs);
        assert_eq!(limits.log_dir, Some(temp.path().join("captured-logs")));

        let default_config = OutputConfig {
            log_dir: None,
            ..config
        };
        let default_limits =
            resolve_output_limits(Some(&default_config), temp.path()).expect("default log dir");
        assert_eq!(
            default_limits.log_dir,
            Some(env::temp_dir().join("build-service"))
        );
    }

    #[test]
    fn resolve_log_dir_accepts_absolute_and_rejects_empty_values() {
        let temp = tempdir().expect("tempdir");
        let absolute = temp.path().join("logs");
        assert_eq!(
            resolve_log_dir(absolute.to_str().expect("absolute path"), temp.path())
                .expect("absolute log dir"),
            absolute
        );
        assert!(resolve_log_dir("   ", temp.path()).is_err());
    }

    #[test]
    fn validate_build_id_rejects_invalid_values() {
        for invalid in ["", ".", "..", "bad/id", "bad\\id", "bad\0id"] {
            assert!(
                validate_build_id(invalid).is_err(),
                "expected invalid build id: {invalid:?}"
            );
        }

        validate_build_id("bld_123").expect("valid build id");
    }

    #[test]
    fn line_limiter_uses_log_path_in_suppression_notice() {
        let mut limiter = LineLimiter::new("stdout", STDOUT_MAX_LINES_ENV, Some(1), 0);
        limiter.set_log_path(PathBuf::from("/tmp/build-service/bld_123/stdout.log"));
        let mut output = Vec::new();

        limiter.write_chunk("one\ntwo\n", &mut output).unwrap();
        limiter.finish();
        limiter.write_summary(&mut output, "stdout").unwrap();

        let rendered = String::from_utf8(output).unwrap();
        assert_eq!(
            rendered,
            "one\n[build-service] suppressing stdout output due to limits (full log: /tmp/build-service/bld_123/stdout.log)\n[build-service] 1 more stdout lines suppressed\n"
        );
    }

    #[test]
    fn log_capture_state_disables_after_write_failure() {
        let paths = StreamLogPaths {
            stdout: PathBuf::from("/tmp/stdout.log"),
            stderr: PathBuf::from("/tmp/stderr.log"),
        };
        let mut state = LogCaptureState {
            base_dir: Some(PathBuf::from("/tmp/build-service")),
            sink: Some(BuildLogSink::from_writers(
                paths.clone(),
                Box::new(FailingWriter),
                Box::new(Vec::<u8>::new()),
            )),
            warning_emitted: false,
            pending_events: VecDeque::new(),
        };
        let limits = OutputLimits {
            stdout_max_lines: Some(10),
            stderr_max_lines: Some(10),
            stdout_tail_lines: 0,
            stderr_tail_lines: 0,
            capture_logs: true,
            log_dir: Some(PathBuf::from("/tmp/build-service")),
        };
        let mut output = OutputLimiter::new(&limits);
        output.set_log_paths(&paths);

        state
            .process_event(
                BufferedStreamEvent::Stdout("one\ntwo\n".to_string()),
                &mut output,
            )
            .expect("process event");

        assert!(!state.capture_requested());
        assert!(state.warning_emitted);
        assert!(output.stdout.log_path.is_none());
        assert!(output.stderr.log_path.is_none());
    }

    #[test]
    fn read_responses_buffers_prebuild_events_and_writes_logs() {
        let temp = tempdir().expect("tempdir");
        let log_dir = temp.path().join("captured-logs");
        let body = concat!(
            "{\"type\":\"stdout\",\"data\":\"before-one\\nbefore-two\\n\"}\n",
            "{\"type\":\"build\",\"id\":\"bld_123\",\"status\":\"started\"}\n",
            "{\"type\":\"stderr\",\"data\":\"err-one\\nerr-two\\n\"}\n",
            "{\"type\":\"exit\",\"code\":0,\"timed_out\":false}\n"
        )
        .to_string();
        let (url, handle) = start_ndjson_server(body);
        let response = Client::new().get(url).send().expect("send request");
        let limits = OutputLimits {
            stdout_max_lines: None,
            stderr_max_lines: None,
            stdout_tail_lines: 0,
            stderr_tail_lines: 0,
            capture_logs: true,
            log_dir: Some(log_dir.clone()),
        };

        let result = read_responses(response, &limits).expect("read responses");
        handle.join().expect("join server");

        assert_eq!(result.exit_code, 0);
        assert_eq!(
            fs::read_to_string(log_dir.join("bld_123/stdout.log")).expect("read stdout log"),
            "before-one\nbefore-two\n"
        );
        assert_eq!(
            fs::read_to_string(log_dir.join("bld_123/stderr.log")).expect("read stderr log"),
            "err-one\nerr-two\n"
        );
    }

    #[test]
    fn resolve_timeout_prefers_explicit_then_env_then_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let prev = env::var("BUILD_SERVICE_TIMEOUT").ok();

        env::remove_var("BUILD_SERVICE_TIMEOUT");
        let request = RequestConfig {
            timeout_sec: Some(12),
            cwd: None,
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

    #[test]
    fn expand_workspace_macros_no_macro_skips_git() {
        let temp = tempdir().expect("tempdir");
        let id = expand_workspace_macros("custom_id", temp.path()).expect("expand");
        assert_eq!(id, "custom_id");
    }

    #[test]
    fn expand_workspace_macros_replaces_uid() {
        let temp = tempdir().expect("tempdir");
        // SAFETY: `geteuid` has no preconditions and reads process metadata only.
        let uid = unsafe { libc::geteuid() };

        let id = expand_workspace_macros("custom-{uid}", temp.path()).expect("expand");
        assert_eq!(id, format!("custom-{uid}"));
    }

    #[test]
    fn expand_workspace_macros_replaces_repo() {
        let temp = tempdir().expect("tempdir");
        let repo_name = temp
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("repo name");

        let id = expand_workspace_macros("custom-{repo}", temp.path()).expect("expand");
        assert_eq!(id, format!("custom-{repo_name}"));
    }

    #[test]
    fn expand_workspace_macros_replaces_branch() {
        if !git_available() {
            eprintln!("git not available; skipping test");
            return;
        }
        let temp = tempdir().expect("tempdir");
        init_git_repo(temp.path());
        run_git(temp.path(), &["checkout", "-b", "feature/add-auth"]);

        let id = expand_workspace_macros("myproject-{branch}", temp.path()).expect("expand");
        assert_eq!(id, "myproject-feature/add-auth");
    }

    #[test]
    fn expand_workspace_macros_replaces_uid_and_branch() {
        if !git_available() {
            eprintln!("git not available; skipping test");
            return;
        }
        let temp = tempdir().expect("tempdir");
        init_git_repo(temp.path());
        run_git(temp.path(), &["checkout", "-b", "feature/add-auth"]);
        // SAFETY: `geteuid` has no preconditions and reads process metadata only.
        let uid = unsafe { libc::geteuid() };

        let id = expand_workspace_macros("build-{uid}-{branch}", temp.path()).expect("expand");
        assert_eq!(id, format!("build-{uid}-feature/add-auth"));
    }

    #[test]
    fn expand_workspace_macros_replaces_repo_uid_and_branch() {
        if !git_available() {
            eprintln!("git not available; skipping test");
            return;
        }
        let temp = tempdir().expect("tempdir");
        init_git_repo(temp.path());
        run_git(temp.path(), &["checkout", "-b", "feature/add-auth"]);
        // SAFETY: `geteuid` has no preconditions and reads process metadata only.
        let uid = unsafe { libc::geteuid() };
        let repo_name = temp
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("repo name");

        let id = expand_workspace_macros("{repo}-{uid}-{branch}", temp.path()).expect("expand");
        assert_eq!(id, format!("{repo_name}-{uid}-feature/add-auth"));
    }

    #[test]
    fn get_git_branch_detached_head_returns_detached() {
        if !git_available() {
            eprintln!("git not available; skipping test");
            return;
        }
        let temp = tempdir().expect("tempdir");
        init_git_repo(temp.path());
        let sha = run_git(temp.path(), &["rev-parse", "HEAD"]);
        let output = Command::new("git")
            .arg("checkout")
            .arg(&sha)
            .current_dir(temp.path())
            .output()
            .expect("git checkout");
        assert!(
            output.status.success(),
            "git checkout failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let branch = get_git_branch(temp.path()).expect("branch");
        assert_eq!(branch, "detached");
    }

    #[test]
    fn expand_workspace_macros_errors_outside_repo() {
        let temp = tempdir().expect("tempdir");
        let err = expand_workspace_macros("custom-{branch}", temp.path());
        assert!(err.is_err());
    }

    #[test]
    fn cli_requires_build_subcommand_for_builds() {
        let cli = Cli::try_parse_from(["build-cli", "build", "--timeout", "30", "make", "-j4"])
            .expect("parse build");
        match cli.command {
            Commands::Build(args) => {
                assert_eq!(args.timeout, Some(30));
                assert_eq!(args.command, "make");
                assert_eq!(args.args, vec!["-j4"]);
            }
            _ => panic!("expected build command"),
        }

        assert!(Cli::try_parse_from(["build-cli", "make"]).is_err());
    }

    #[test]
    fn cli_parses_workspace_lifecycle_with_global_endpoint() {
        let cli = Cli::try_parse_from([
            "build-cli",
            "--endpoint",
            "unix:///tmp/build-service.sock",
            "workspace",
            "reset",
            "--workspace-id",
            "custom",
        ])
        .expect("parse workspace reset");

        assert_eq!(
            cli.endpoint.as_deref(),
            Some("unix:///tmp/build-service.sock")
        );
        match cli.command {
            Commands::Workspace {
                command: WorkspaceCommand::Reset(args),
            } => assert_eq!(args.workspace_id.as_deref(), Some("custom")),
            _ => panic!("expected workspace reset"),
        }
    }

    #[test]
    fn resolve_lifecycle_workspace_id_sanitizes_macros() {
        let temp = tempdir().expect("tempdir");
        let id =
            resolve_lifecycle_workspace_id(Some("feature/add-auth".to_string()), None, temp.path())
                .expect("workspace id");

        assert_eq!(id, "feature-add-auth");
    }
}
