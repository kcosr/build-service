use std::collections::HashMap;
use std::env;
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
}

#[derive(Debug, Clone)]
enum Endpoint {
    Http { base: String },
    Unix { path: PathBuf },
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

    let build = match run_build(&request, &source_archive, &endpoint, token.as_deref()) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("build request failed: {err}");
            return ExitCode::from(1);
        }
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

        let mut found = false;
        if collect_recursive_prefix(pattern, &root, &exclude_patterns, &mut matched_files)? {
            found = true;
        }

        for entry in entries {
            let path = entry.map_err(|err| io::Error::other(err.to_string()))?;
            found = true;
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

        if !found {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("pattern {pattern} matched nothing"),
            ));
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
) -> io::Result<BuildResult> {
    let (client, url, send_auth) = match endpoint {
        Endpoint::Http { base } => (
            Client::builder()
                .timeout(None)
                .build()
                .map_err(io::Error::other)?,
            format!("{base}/v1/builds"),
            true,
        ),
        Endpoint::Unix { path } => {
            let client = Client::builder()
                .unix_socket(path.clone())
                .timeout(None)
                .build()
                .map_err(io::Error::other)?;
            (client, "http://localhost/v1/builds".to_string(), false)
        }
    };

    let metadata = serde_json::to_string(request).map_err(io::Error::other)?;
    let source_part = Part::file(source_archive.path()).map_err(io::Error::other)?;
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

    let response = builder.send().map_err(io::Error::other)?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_else(|_| "".to_string());
        return Err(io::Error::other(format!(
            "server returned {status}: {body}"
        )));
    }

    read_responses(response)
}

fn read_responses(response: reqwest::blocking::Response) -> io::Result<BuildResult> {
    let mut reader = BufReader::new(response);
    let mut line = String::new();
    let mut exit_code: Option<i32> = None;
    let mut timed_out = false;
    let mut artifacts: Option<ArtifactArchive> = None;

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }

        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }

        let event: ResponseEvent = serde_json::from_str(trimmed).map_err(io::Error::other)?;

        match event {
            ResponseEvent::Stdout { data } => {
                let mut stdout = io::stdout();
                stdout.write_all(data.as_bytes())?;
                stdout.flush()?;
            }
            ResponseEvent::Stderr { data } => {
                let mut stderr = io::stderr();
                stderr.write_all(data.as_bytes())?;
                stderr.flush()?;
            }
            ResponseEvent::Error { message, .. } => {
                if let Some(message) = message {
                    let mut stderr = io::stderr();
                    writeln!(stderr, "{message}")?;
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

    match exit_code {
        Some(code) => Ok(BuildResult {
            exit_code: code,
            timed_out,
            artifacts,
        }),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing exit event",
        )),
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
    use std::sync::Mutex;

    #[test]
    fn normalize_exit_code_clamps() {
        assert_eq!(normalize_exit_code(-1), 1);
        assert_eq!(normalize_exit_code(0), 0);
        assert_eq!(normalize_exit_code(255), 255);
        assert_eq!(normalize_exit_code(300), 255);
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
    fn resolve_timeout_prefers_explicit_then_env_then_config() {
        static ENV_LOCK: Mutex<()> = Mutex::new(());
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
