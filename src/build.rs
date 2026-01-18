use std::collections::HashMap;
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::artifacts::{collect_artifacts_zip, ArtifactError};
use crate::config::Config;
use crate::protocol::{ArtifactArchive, Request, ResponseEvent, SCHEMA_VERSION};
use crate::user::{lookup_group_gid, lookup_user, lookup_user_by_name, UserInfo};
use crate::validation::{
    validate_cwd, validate_make_args, validate_relative_path, ValidationError,
};

const TIMEOUT_EXIT_CODE: i32 = 124;
const TIMEOUT_KILL_GRACE_SECS: u64 = 5;
const OUTPUT_CHUNK_SIZE: usize = 4096;

#[derive(Debug)]
pub struct BuildError {
    pub code: &'static str,
    pub message: String,
    pub pattern: Option<String>,
}

impl BuildError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            pattern: None,
        }
    }

    fn with_pattern(code: &'static str, message: impl Into<String>, pattern: String) -> Self {
        Self {
            code,
            message: message.into(),
            pattern: Some(pattern),
        }
    }
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for BuildError {}

pub struct ValidatedRequest {
    pub request: Request,
    pub command_path: PathBuf,
    pub timeout_sec: u64,
}

pub fn validate_request(request: Request, config: &Config) -> Result<ValidatedRequest, BuildError> {
    if request.schema_version_or_default() != SCHEMA_VERSION {
        return Err(BuildError::new(
            "schema_version",
            format!(
                "unsupported schema_version {}",
                request.schema_version_or_default()
            ),
        ));
    }

    if request.command.trim().is_empty() {
        return Err(BuildError::new("command", "command must not be empty"));
    }

    let command_path = config
        .build
        .commands
        .get(&request.command)
        .cloned()
        .ok_or_else(|| {
            BuildError::new(
                "command_not_allowed",
                format!("command {} not allowed", request.command),
            )
        })?;

    let timeout = request
        .timeout_sec
        .unwrap_or(config.build.timeouts.default_sec);
    if timeout == 0 {
        return Err(BuildError::new(
            "timeout",
            "timeout_sec must be greater than zero",
        ));
    }
    let timeout = timeout.min(config.build.timeouts.max_sec);

    if let Some(env) = &request.env {
        for key in env.keys() {
            if key.trim().is_empty() {
                return Err(BuildError::new("env", "env keys must not be empty"));
            }
            if !config
                .build
                .environment
                .allow
                .iter()
                .any(|allowed| allowed == key)
            {
                return Err(BuildError::new(
                    "env_not_allowed",
                    format!("env {key} is not allowed"),
                ));
            }
        }
    }

    for pattern in &request.artifacts.include {
        if let Err(err) = crate::validation::validate_relative_pattern(pattern, "artifacts.include")
        {
            return Err(BuildError::new("artifact_pattern", err.to_string()));
        }
    }
    for pattern in &request.artifacts.exclude {
        if let Err(err) = crate::validation::validate_relative_pattern(pattern, "artifacts.exclude")
        {
            return Err(BuildError::new("artifact_pattern", err.to_string()));
        }
    }

    if let Some(cwd) = &request.cwd {
        if let Err(err) = validate_relative_path(cwd, "cwd") {
            return Err(BuildError::new("cwd", err.to_string()));
        }
    }

    Ok(ValidatedRequest {
        request,
        command_path,
        timeout_sec: timeout,
    })
}

pub fn execute_build(
    validated: ValidatedRequest,
    config: std::sync::Arc<Config>,
    source_archive: PathBuf,
    sender: Sender<ResponseEvent>,
) {
    if let Err(err) = run_build(validated, &config, &source_archive, &sender) {
        let _ = sender.blocking_send(ResponseEvent::Error {
            code: err.code.to_string(),
            message: Some(err.message),
            pattern: err.pattern,
        });
        let _ = sender.blocking_send(ResponseEvent::Exit {
            code: 1,
            timed_out: false,
            artifacts: None,
        });
    }

    if let Err(err) = std::fs::remove_file(&source_archive) {
        warn!(
            "failed to remove source archive {:?}: {err}",
            source_archive
        );
    }
}

fn run_build(
    validated: ValidatedRequest,
    config: &Config,
    source_archive: &Path,
    sender: &Sender<ResponseEvent>,
) -> Result<(), BuildError> {
    let build_id = format!("bld_{}", Uuid::new_v4().simple());

    sender
        .blocking_send(ResponseEvent::Build {
            id: build_id.clone(),
            status: "started".to_string(),
        })
        .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;

    let run_as = resolve_run_as(config)?;

    let workspace = prepare_workspace(config, &build_id, source_archive)?;
    let cleanup_path = workspace.clone();

    let result = run_build_in_workspace(&validated, config, &run_as, &workspace, &build_id, sender);

    if let Err(err) = std::fs::remove_dir_all(&cleanup_path) {
        warn!("failed to cleanup workspace {:?}: {err}", cleanup_path);
    }

    result
}

fn run_build_in_workspace(
    validated: &ValidatedRequest,
    config: &Config,
    run_as: &RunAs,
    workspace_root: &Path,
    build_id: &str,
    sender: &Sender<ResponseEvent>,
) -> Result<(), BuildError> {
    let cwd = resolve_cwd(workspace_root, validated.request.cwd.as_deref())?;

    if validated.request.command == "make" {
        validate_make_args(&validated.request.args, &cwd, workspace_root)
            .map_err(to_validation_error)?;
    }

    let request_id = validated.request.request_id.as_deref().unwrap_or("-");
    info!(
        "build started build_id={} request_id={} cwd={} args={:?}",
        build_id,
        request_id,
        cwd.display(),
        validated.request.args
    );

    let env = build_env(config, &validated.request.env, &run_as.user);

    let mut command = Command::new(&validated.command_path);
    command
        .args(&validated.request.args)
        .current_dir(&cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();

    for (key, value) in env {
        command.env(key, value);
    }

    configure_command(&mut command, run_as)?;

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return Err(BuildError::new(
                "spawn_failed",
                format!("failed to spawn build: {err}"),
            ));
        }
    };

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BuildError::new("io", "failed to capture stdout from build"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BuildError::new("io", "failed to capture stderr from build"))?;

    let stdout_handle = spawn_output_thread(stdout, sender.clone(), StreamKind::Stdout);
    let stderr_handle = spawn_output_thread(stderr, sender.clone(), StreamKind::Stderr);

    let start = Instant::now();
    let (exit_code, timed_out) = wait_with_timeout(&mut child, validated.timeout_sec)
        .map_err(|err| BuildError::new("wait_failed", err.to_string()))?;

    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    if timed_out {
        warn!(
            "build timed out build_id={} request_id={} duration_sec={} cwd={}",
            build_id,
            request_id,
            start.elapsed().as_secs(),
            cwd.display()
        );
    } else {
        let level = if exit_code == 0 { "info" } else { "error" };
        if level == "info" {
            info!(
                "build completed build_id={} exit_code={} duration_sec={}",
                build_id,
                exit_code,
                start.elapsed().as_secs()
            );
        } else {
            error!(
                "build completed build_id={} exit_code={} duration_sec={}",
                build_id,
                exit_code,
                start.elapsed().as_secs()
            );
        }
    }

    if timed_out || exit_code != 0 {
        sender
            .blocking_send(ResponseEvent::Exit {
                code: exit_code,
                timed_out,
                artifacts: None,
            })
            .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;
        return Ok(());
    }

    let artifacts = match collect_artifacts_zip(
        workspace_root,
        &validated.request.artifacts,
        &config.artifacts,
        build_id,
    ) {
        Ok(archive) => archive,
        Err(err) => {
            let build_err = map_artifact_error(err);
            sender
                .blocking_send(ResponseEvent::Error {
                    code: build_err.code.to_string(),
                    message: Some(build_err.message.clone()),
                    pattern: build_err.pattern.clone(),
                })
                .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;
            sender
                .blocking_send(ResponseEvent::Exit {
                    code: 1,
                    timed_out: false,
                    artifacts: None,
                })
                .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;
            return Ok(());
        }
    };

    sender
        .blocking_send(ResponseEvent::Exit {
            code: exit_code,
            timed_out,
            artifacts,
        })
        .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;

    Ok(())
}

fn resolve_cwd(root: &Path, cwd: Option<&str>) -> Result<PathBuf, BuildError> {
    let candidate = match cwd {
        None => root.to_path_buf(),
        Some(value) if value.trim().is_empty() => root.to_path_buf(),
        Some(value) => {
            let rel = validate_relative_path(value, "cwd").map_err(to_validation_error)?;
            root.join(rel)
        }
    };

    validate_cwd(&candidate, root).map_err(to_validation_error)
}

fn to_validation_error(err: ValidationError) -> BuildError {
    BuildError::new("invalid_path", err.to_string())
}

fn map_artifact_error(err: ArtifactError) -> BuildError {
    match err {
        ArtifactError::GlobMiss { pattern } => BuildError::with_pattern(
            "artifact_glob_miss",
            "artifact pattern matched nothing",
            pattern,
        ),
        other => BuildError::new("artifact_collection_failed", other.to_string()),
    }
}

fn prepare_workspace(
    config: &Config,
    build_id: &str,
    source_archive: &Path,
) -> Result<PathBuf, BuildError> {
    let workspace_root = config.build.workspace_root.join("builds");
    std::fs::create_dir_all(&workspace_root).map_err(|err| {
        BuildError::new(
            "workspace_create_failed",
            format!("failed to create workspace root: {err}"),
        )
    })?;

    let workspace = workspace_root.join(build_id);
    std::fs::create_dir_all(&workspace).map_err(|err| {
        BuildError::new(
            "workspace_create_failed",
            format!("failed to create workspace: {err}"),
        )
    })?;

    if let Err(err) =
        extract_source_archive(source_archive, &workspace, config.build.max_extracted_bytes)
    {
        let _ = std::fs::remove_dir_all(&workspace);
        return Err(err);
    }

    Ok(workspace)
}

fn extract_source_archive(
    source_archive: &Path,
    dest: &Path,
    max_extracted_bytes: u64,
) -> Result<(), BuildError> {
    use std::os::unix::fs::PermissionsExt;

    let file = std::fs::File::open(source_archive).map_err(|err| {
        BuildError::new(
            "source_archive",
            format!("failed to open source archive: {err}"),
        )
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|err| {
        BuildError::new(
            "source_archive",
            format!("failed to read source archive: {err}"),
        )
    })?;

    let mut extracted_bytes = 0u64;
    let mut buffer = vec![0u8; 8192];

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|err| {
            BuildError::new("source_archive", format!("failed to read zip entry: {err}"))
        })?;

        let Some(enclosed) = file.enclosed_name() else {
            return Err(BuildError::new(
                "source_archive",
                "zip entry had invalid path",
            ));
        };

        let out_path = dest.join(enclosed);
        let unix_mode = file.unix_mode();

        if file.is_dir() {
            std::fs::create_dir_all(&out_path)
                .map_err(|err| BuildError::new("source_archive", format!("mkdir failed: {err}")))?;
            continue;
        }

        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|err| BuildError::new("source_archive", format!("mkdir failed: {err}")))?;
        }

        let mut outfile = std::fs::File::create(&out_path).map_err(|err| {
            BuildError::new("source_archive", format!("create file failed: {err}"))
        })?;
        loop {
            let bytes = file.read(&mut buffer).map_err(|err| {
                BuildError::new("source_archive", format!("read zip entry failed: {err}"))
            })?;
            if bytes == 0 {
                break;
            }

            extracted_bytes = extracted_bytes.saturating_add(bytes as u64);
            if extracted_bytes > max_extracted_bytes {
                return Err(BuildError::new(
                    "source_archive",
                    format!(
                        "extracted size exceeds max_extracted_bytes ({max_extracted_bytes} bytes)"
                    ),
                ));
            }

            outfile.write_all(&buffer[..bytes]).map_err(|err| {
                BuildError::new("source_archive", format!("write file failed: {err}"))
            })?;
        }

        // Restore Unix permissions if present in zip
        if let Some(mode) = unix_mode {
            std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(mode)).map_err(
                |err| BuildError::new("source_archive", format!("set permissions failed: {err}")),
            )?;
        }
    }

    Ok(())
}

struct RunAs {
    user: UserInfo,
    gid: u32,
    set_ids: bool,
}

fn resolve_run_as(config: &Config) -> Result<RunAs, BuildError> {
    let set_ids = config.build.run_as_user.is_some() || config.build.run_as_group.is_some();

    let user = if let Some(user) = &config.build.run_as_user {
        lookup_user_by_name(user).map_err(|err| {
            BuildError::new(
                "run_as_user",
                format!("failed to resolve run_as_user: {err}"),
            )
        })?
    } else {
        let uid = unsafe { libc::getuid() };
        lookup_user(uid).map_err(|err| {
            BuildError::new(
                "run_as_user",
                format!("failed to resolve service user: {err}"),
            )
        })?
    };

    let gid = if let Some(group) = &config.build.run_as_group {
        lookup_group_gid(group).map_err(|err| {
            BuildError::new(
                "run_as_group",
                format!("failed to resolve run_as_group: {err}"),
            )
        })?
    } else {
        user.gid
    };

    Ok(RunAs { user, gid, set_ids })
}

fn build_env(
    config: &Config,
    request_env: &Option<HashMap<String, String>>,
    user: &UserInfo,
) -> Vec<(String, String)> {
    let env_map: HashMap<String, String> = std::env::vars().collect();
    let mut result = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for key in &config.build.environment.allow {
        if !seen.insert(key) {
            continue;
        }

        match key.as_str() {
            "HOME" => {
                result.push((key.clone(), user.home_dir.to_string_lossy().into_owned()));
            }
            "USER" | "LOGNAME" => {
                result.push((key.clone(), user.username.clone()));
            }
            _ => {
                if let Some(value) = request_env.as_ref().and_then(|env| env.get(key)) {
                    result.push((key.clone(), value.clone()));
                } else if let Some(value) = env_map.get(key) {
                    result.push((key.clone(), value.clone()));
                }
            }
        }
    }

    result
}

fn configure_command(command: &mut Command, run_as: &RunAs) -> Result<(), BuildError> {
    let should_set_ids = run_as.set_ids;
    let username = run_as.user.username.clone();
    let gid = run_as.gid;
    let uid = run_as.user.uid;

    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }

            if should_set_ids {
                let c_username = CString::new(username.clone())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid username"))?;
                if libc::initgroups(c_username.as_ptr(), gid as libc::gid_t) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setgid(gid as libc::gid_t) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(uid as libc::uid_t) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }

    Ok(())
}

fn spawn_output_thread(
    stream: impl Read + Send + 'static,
    sender: Sender<ResponseEvent>,
    kind: StreamKind,
) -> thread::JoinHandle<()> {
    thread::spawn(move || stream_output(stream, sender, kind))
}

#[derive(Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

fn stream_output(mut reader: impl Read, sender: Sender<ResponseEvent>, kind: StreamKind) {
    let mut buf = vec![0u8; OUTPUT_CHUNK_SIZE];

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let data = String::from_utf8_lossy(&buf[..n]).into_owned();
                let event = match kind {
                    StreamKind::Stdout => ResponseEvent::Stdout { data },
                    StreamKind::Stderr => ResponseEvent::Stderr { data },
                };

                if sender.blocking_send(event).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn wait_with_timeout(child: &mut Child, timeout_sec: u64) -> io::Result<(i32, bool)> {
    let timeout = Duration::from_secs(timeout_sec);
    let start = Instant::now();

    loop {
        if let Some(status) = child.try_wait()? {
            let code = status.code().unwrap_or_else(|| match status.signal() {
                Some(signal) => 128 + signal,
                None => 1,
            });
            return Ok((code, false));
        }

        if start.elapsed() >= timeout {
            break;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    if let Err(err) = child.kill() {
        warn!(
            "failed to kill timed-out process (pid {}): {}",
            child.id(),
            err
        );
    }
    let start_kill = Instant::now();

    loop {
        if let Some(status) = child.try_wait()? {
            let code = status.code().unwrap_or_else(|| match status.signal() {
                Some(signal) => 128 + signal,
                None => 1,
            });
            return Ok((code, true));
        }

        if start_kill.elapsed() >= Duration::from_secs(TIMEOUT_KILL_GRACE_SECS) {
            break;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    if let Err(err) = child.kill() {
        warn!(
            "failed to force kill timed-out process (pid {}): {}",
            child.id(),
            err
        );
    }
    Ok((TIMEOUT_EXIT_CODE, true))
}

#[allow(clippy::module_name_repetitions)]
pub fn artifacts_for_build(build_id: &str, config: &Config) -> Option<ArtifactArchive> {
    let path = config
        .artifacts
        .storage_root
        .join(build_id)
        .join("artifacts.zip");
    let size = match std::fs::metadata(&path) {
        Ok(meta) => meta.len(),
        Err(_) => return None,
    };

    Some(ArtifactArchive {
        path: format!("/v1/builds/{build_id}/artifacts.zip"),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{tempdir, NamedTempFile};
    use zip::write::FileOptions;
    use zip::ZipWriter;

    #[test]
    fn extract_source_archive_enforces_max_extracted_bytes() {
        let temp = tempdir().expect("tempdir");
        let source = create_test_zip("input.txt", b"0123456789").expect("zip");
        let dest = temp.path().join("workspace");
        std::fs::create_dir_all(&dest).expect("dest dir");

        let err = extract_source_archive(source.path(), &dest, 5).unwrap_err();
        assert_eq!(err.code, "source_archive");
        assert!(
            err.message.contains("max_extracted_bytes"),
            "unexpected error: {}",
            err.message
        );
    }

    fn create_test_zip(name: &str, contents: &[u8]) -> io::Result<NamedTempFile> {
        let temp = NamedTempFile::new()?;
        let file = temp.reopen()?;
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file(name, options)?;
        zip.write_all(contents)?;
        zip.finish()?;
        Ok(temp)
    }
}
