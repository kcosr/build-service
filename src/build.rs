use std::ffi::CString;
use std::io::{self, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::artifacts::{collect_artifacts, ArtifactError};
use crate::config::{Config, ProjectConfig};
use crate::protocol::{Request, ResponseEvent, SCHEMA_VERSION};
use crate::user::{lookup_group_gid, lookup_user, lookup_user_by_name, UserInfo};
use crate::validation::{validate_cwd, validate_make_args, ValidationError};

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
    pub project: ProjectConfig,
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

    if request.project_id.trim().is_empty() {
        return Err(BuildError::new(
            "project_id",
            "project_id must not be empty",
        ));
    }

    let project = config
        .projects
        .iter()
        .find(|project| project.id() == request.project_id)
        .cloned()
        .ok_or_else(|| {
            BuildError::new(
                "project_not_found",
                format!("project {} not found", request.project_id),
            )
        })?;

    if request.command.trim().is_empty() {
        return Err(BuildError::new("command", "command must not be empty"));
    }

    if !project.commands().iter().any(|cmd| cmd == &request.command) {
        return Err(BuildError::new(
            "command_not_allowed",
            format!("command {} not allowed", request.command),
        ));
    }

    let command_path = config
        .build
        .commands
        .get(&request.command)
        .cloned()
        .ok_or_else(|| {
            BuildError::new(
                "command_unknown",
                format!("command {} not configured", request.command),
            )
        })?;

    if request.ref_override.is_some() && !matches!(project, ProjectConfig::Repo { .. }) {
        return Err(BuildError::new(
            "ref_not_allowed",
            "ref overrides are only supported for repo projects",
        ));
    }

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

    Ok(ValidatedRequest {
        request,
        project,
        command_path,
        timeout_sec: timeout,
    })
}

pub fn execute_build(
    validated: ValidatedRequest,
    config: std::sync::Arc<Config>,
    sender: Sender<ResponseEvent>,
) {
    if let Err(err) = run_build(validated, &config, &sender) {
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
}

fn run_build(
    validated: ValidatedRequest,
    config: &Config,
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

    let workspace = prepare_workspace(&validated.request, &validated.project, config, &build_id)?;
    let cleanup_path = workspace.cleanup.clone();

    let result = run_build_in_workspace(&validated, config, &run_as, &workspace, &build_id, sender);

    if let Some(path) = cleanup_path {
        if let Err(err) = std::fs::remove_dir_all(&path) {
            warn!("failed to cleanup workspace {:?}: {err}", path);
        }
    }

    result
}

fn run_build_in_workspace(
    validated: &ValidatedRequest,
    config: &Config,
    run_as: &RunAs,
    workspace: &ProjectWorkspace,
    build_id: &str,
    sender: &Sender<ResponseEvent>,
) -> Result<(), BuildError> {
    let cwd = resolve_cwd(&workspace.root, validated.request.cwd.as_deref())?;

    if validated.request.command == "make" {
        validate_make_args(&validated.request.args, &cwd, &workspace.root)
            .map_err(to_validation_error)?;
    }

    let request_id = validated.request.request_id.as_deref().unwrap_or("-");
    info!(
        "build started build_id={} project_id={} request_id={} cwd={} args={:?}",
        build_id,
        validated.project.id(),
        request_id,
        cwd.display(),
        validated.request.args
    );

    let env = build_env(config, &run_as.user);

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

    configure_command(&mut command, run_as);

    let mut child = command
        .spawn()
        .map_err(|err| BuildError::new("spawn_failed", format!("failed to spawn build: {err}")))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BuildError::new("spawn_failed", "failed to capture stdout".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BuildError::new("spawn_failed", "failed to capture stderr".to_string()))?;

    let stdout_sender = sender.clone();
    let stderr_sender = sender.clone();
    let stdout_handle =
        thread::spawn(move || stream_output(stdout, stdout_sender, StreamKind::Stdout));
    let stderr_handle =
        thread::spawn(move || stream_output(stderr, stderr_sender, StreamKind::Stderr));

    let start = Instant::now();
    let (exit_code, timed_out) = wait_with_timeout(&mut child, validated.timeout_sec)
        .map_err(|err| BuildError::new("wait_failed", format!("wait failed: {err}")))?;

    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    if timed_out {
        warn!(
            "build timed out build_id={} project_id={} request_id={} duration_sec={} cwd={}",
            build_id,
            validated.project.id(),
            request_id,
            start.elapsed().as_secs(),
            cwd.display()
        );
    } else {
        let level = if exit_code == 0 { "info" } else { "error" };
        if level == "info" {
            info!(
                "build completed build_id={} project_id={} exit_code={} duration_sec={}",
                build_id,
                validated.project.id(),
                exit_code,
                start.elapsed().as_secs()
            );
        } else {
            error!(
                "build completed build_id={} project_id={} exit_code={} duration_sec={}",
                build_id,
                validated.project.id(),
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

    let artifacts = match collect_artifacts(
        &workspace.root,
        validated.project.artifacts(),
        &config.artifacts,
        build_id,
    ) {
        Ok(artifacts) => artifacts,
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
            artifacts: Some(artifacts),
        })
        .map_err(|_| BuildError::new("stream_closed", "client disconnected"))?;

    Ok(())
}

fn resolve_cwd(root: &Path, cwd: Option<&str>) -> Result<PathBuf, BuildError> {
    let candidate = match cwd {
        None => root.to_path_buf(),
        Some(value) if value.trim().is_empty() => root.to_path_buf(),
        Some(value) => {
            let path = Path::new(value);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                root.join(path)
            }
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
    request: &Request,
    project: &ProjectConfig,
    config: &Config,
    build_id: &str,
) -> Result<ProjectWorkspace, BuildError> {
    match project {
        ProjectConfig::Repo {
            repo_url,
            repo_ref,
            repo_subdir,
            ..
        } => {
            let workspace_root = config.build.workspace_root.join("builds");
            std::fs::create_dir_all(&workspace_root).map_err(|err| {
                BuildError::new(
                    "workspace_create_failed",
                    format!("failed to create workspace root: {err}"),
                )
            })?;
            let workspace = workspace_root.join(build_id);
            let ref_name = request.ref_override.as_deref().unwrap_or(repo_ref);

            run_git_clone(repo_url, &workspace)?;
            run_git_checkout(&workspace, ref_name)?;

            let root = resolve_repo_subdir(&workspace, repo_subdir)?;

            Ok(ProjectWorkspace {
                root,
                cleanup: Some(workspace),
            })
        }
        ProjectConfig::Path { path_root, .. } => {
            let root = std::fs::canonicalize(path_root).map_err(|err| {
                BuildError::new(
                    "path_root_invalid",
                    format!("failed to resolve path_root: {err}"),
                )
            })?;
            Ok(ProjectWorkspace {
                root,
                cleanup: None,
            })
        }
    }
}

fn resolve_repo_subdir(workspace: &Path, repo_subdir: &str) -> Result<PathBuf, BuildError> {
    let candidate = workspace.join(repo_subdir);
    let root = std::fs::canonicalize(&candidate).map_err(|err| {
        BuildError::new(
            "repo_subdir_invalid",
            format!("failed to resolve repo_subdir: {err}"),
        )
    })?;

    if !root.starts_with(workspace) {
        return Err(BuildError::new(
            "repo_subdir_invalid",
            "repo_subdir escapes repository root",
        ));
    }

    Ok(root)
}

fn run_git_clone(repo_url: &str, workspace: &Path) -> Result<(), BuildError> {
    let output = Command::new("git")
        .arg("clone")
        .arg(repo_url)
        .arg(workspace)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|err| BuildError::new("repo_clone_failed", format!("git clone failed: {err}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(BuildError::new(
            "repo_clone_failed",
            format!("git clone failed: {stderr}"),
        ));
    }

    Ok(())
}

fn run_git_checkout(workspace: &Path, reference: &str) -> Result<(), BuildError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .arg("checkout")
        .arg(reference)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|err| {
            BuildError::new(
                "repo_checkout_failed",
                format!("git checkout failed: {err}"),
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(BuildError::new(
            "repo_checkout_failed",
            format!("git checkout failed: {stderr}"),
        ));
    }

    Ok(())
}

fn configure_command(command: &mut Command, run_as: &RunAs) {
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

fn build_env(config: &Config, user: &UserInfo) -> Vec<(String, String)> {
    let env_map: std::collections::HashMap<String, String> = std::env::vars().collect();
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
                if let Some(value) = env_map.get(key) {
                    result.push((key.clone(), value.clone()));
                }
            }
        }
    }

    result
}

struct ProjectWorkspace {
    root: PathBuf,
    cleanup: Option<PathBuf>,
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

#[derive(Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

fn wait_with_timeout(child: &mut Child, timeout_sec: u64) -> io::Result<(i32, bool)> {
    let timeout = Duration::from_secs(timeout_sec);
    let start = Instant::now();

    loop {
        if let Some(status) = child.try_wait()? {
            let code = exit_status_code(status);
            return Ok((code, false));
        }

        if start.elapsed() >= timeout {
            break;
        }

        thread::sleep(Duration::from_millis(200));
    }

    let pid = child.id() as i32;
    if pid > 0 {
        let _ = unsafe { libc::killpg(pid, libc::SIGTERM) };
    }

    let kill_deadline = Instant::now() + Duration::from_secs(TIMEOUT_KILL_GRACE_SECS);
    loop {
        if let Some(_status) = child.try_wait()? {
            return Ok((TIMEOUT_EXIT_CODE, true));
        }

        if Instant::now() >= kill_deadline {
            break;
        }

        thread::sleep(Duration::from_millis(200));
    }

    if pid > 0 {
        let _ = unsafe { libc::killpg(pid, libc::SIGKILL) };
    }

    let _ = child.wait();
    Ok((TIMEOUT_EXIT_CODE, true))
}

fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    if let Some(signal) = status.signal() {
        return 128 + signal;
    }
    1
}
