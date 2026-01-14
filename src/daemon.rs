use std::ffi::CString;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tracing::{error, info, warn};

use crate::config::{Config, SocketModeError};
use crate::protocol::{Request, ResponseEvent, SCHEMA_VERSION};
use crate::user::{lookup_group_gid, lookup_user, UserError, UserInfo};
use crate::validation::{validate_cwd, validate_make_args, ValidationError};

const TIMEOUT_EXIT_CODE: i32 = 124;
const TIMEOUT_KILL_GRACE_SECS: u64 = 5;
const OUTPUT_CHUNK_SIZE: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("socket setup failed: {0}")]
    SocketSetup(#[from] io::Error),

    #[error("invalid socket mode: {0}")]
    SocketMode(#[from] SocketModeError),

    #[error("group lookup failed: {0}")]
    GroupLookup(#[from] UserError),
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("failed to read request: {0}")]
    Io(#[from] io::Error),

    #[error("invalid request: {0}")]
    Json(#[from] serde_json::Error),

    #[error("unsupported schema_version {0}")]
    SchemaVersion(String),

    #[error("command not allowed: {0}")]
    CommandNotAllowed(String),

    #[error(transparent)]
    Validation(#[from] ValidationError),

    #[error(transparent)]
    User(#[from] UserError),

    #[error("missing request payload")]
    EmptyRequest,
}

#[derive(Debug, Clone, Copy)]
struct PeerCred {
    uid: u32,
    gid: u32,
}

#[derive(Debug, Clone)]
struct PeerIdentity {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

pub fn run(config: Config) -> Result<(), DaemonError> {
    let listener = setup_socket(&config)?;
    let config = Arc::new(config);

    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let cfg = Arc::clone(&config);
                thread::spawn(move || {
                    if let Err(err) = handle_connection(stream, cfg) {
                        warn!("connection handling failed: {err}");
                    }
                });
            }
            Err(err) => {
                warn!("socket accept failed: {err}");
            }
        }
    }
}

fn setup_socket(config: &Config) -> Result<UnixListener, DaemonError> {
    let socket_path = &config.service.socket_path;

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if socket_path.exists() {
        let meta = std::fs::symlink_metadata(socket_path)?;
        if !meta.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("socket path exists and is not a socket: {socket_path:?}"),
            )
            .into());
        }
        std::fs::remove_file(socket_path)?;
    }

    let old_umask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(socket_path)?;
    unsafe { libc::umask(old_umask) };

    let gid = lookup_group_gid(&config.service.socket_group)?;
    apply_socket_permissions(socket_path, gid, config.service.parse_socket_mode()?)?;

    Ok(listener)
}

fn apply_socket_permissions(path: &Path, gid: u32, mode: u32) -> io::Result<()> {
    let gid_t = gid as libc::gid_t;
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid socket path"))?;
    let uid = !0 as libc::uid_t;
    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid_t) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let permissions = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, permissions)?;

    Ok(())
}

fn handle_connection(stream: UnixStream, config: Arc<Config>) -> Result<(), RequestError> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = BufWriter::new(stream);

    let cred = match peer_cred(reader.get_ref()) {
        Ok(cred) => cred,
        Err(err) => {
            send_error(&mut writer, &err.to_string());
            return Err(err);
        }
    };
    let groups = match peer_groups(reader.get_ref()) {
        Ok(groups) => groups,
        Err(err) => {
            send_error(&mut writer, &format!("failed to read peer groups: {err}"));
            return Err(RequestError::Io(err));
        }
    };
    let peer = PeerIdentity {
        uid: cred.uid,
        gid: cred.gid,
        groups,
    };
    let user = match lookup_user(cred.uid) {
        Ok(user) => user,
        Err(err) => {
            send_error(&mut writer, &err.to_string());
            return Err(RequestError::User(err));
        }
    };

    let request = match read_request(&mut reader) {
        Ok(request) => request,
        Err(err) => {
            send_error(&mut writer, &err.to_string());
            return Err(err);
        }
    };
    let prepared = match prepare_request(&request, &config, &user) {
        Ok(prepared) => prepared,
        Err(err) => {
            send_error(&mut writer, &err.to_string());
            return Err(err);
        }
    };

    let request_id = request.request_id.as_deref().unwrap_or("-").to_string();

    info!(
        "build started user={} uid={} cwd={} args={:?} request_id={}",
        user.username,
        peer.uid,
        prepared.cwd.display(),
        request.args,
        request_id
    );

    if let Err(err) = run_build(writer, &request, &prepared, &config, &user, &peer) {
        error!(
            "build failed user={} uid={} request_id={} err={err}",
            user.username, peer.uid, request_id
        );
    }

    Ok(())
}

struct PreparedRequest {
    command_path: PathBuf,
    cwd: PathBuf,
    timeout_sec: u64,
    args: Vec<String>,
}

fn prepare_request(
    request: &Request,
    config: &Config,
    user: &UserInfo,
) -> Result<PreparedRequest, RequestError> {
    if request.schema_version_or_default() != SCHEMA_VERSION {
        return Err(RequestError::SchemaVersion(
            request.schema_version_or_default().to_string(),
        ));
    }

    let command_path = config
        .build
        .commands
        .get(&request.command)
        .cloned()
        .ok_or_else(|| RequestError::CommandNotAllowed(request.command.clone()))?;

    let container_root = config
        .build
        .path_mapping
        .resolve_container_root(&user.username, &config.build.workspace_root);
    let allowed_root = config
        .build
        .path_mapping
        .resolve_host_root(&user.username, &config.build.workspace_root);
    let mapped_cwd = map_container_path(Path::new(&request.cwd), &container_root, &allowed_root);
    let cwd = validate_cwd(&mapped_cwd, &allowed_root)?;
    let mapped_args = map_request_args(&request.args, &container_root, &allowed_root);
    validate_make_args(&mapped_args, &cwd, &allowed_root)?;

    let timeout = request
        .timeout_sec
        .unwrap_or(config.build.timeouts.default_sec)
        .min(config.build.timeouts.max_sec);

    Ok(PreparedRequest {
        command_path,
        cwd,
        timeout_sec: timeout,
        args: mapped_args,
    })
}

fn read_request(reader: &mut BufReader<UnixStream>) -> Result<Request, RequestError> {
    let mut line = String::new();
    let bytes = reader.read_line(&mut line)?;
    if bytes == 0 {
        return Err(RequestError::EmptyRequest);
    }

    let trimmed = line.trim_end();
    if trimmed.is_empty() {
        return Err(RequestError::EmptyRequest);
    }

    Ok(serde_json::from_str(trimmed)?)
}

fn map_container_path(path: &Path, container_root: &Path, host_root: &Path) -> PathBuf {
    if path.starts_with(host_root) {
        return path.to_path_buf();
    }
    if let Ok(stripped) = path.strip_prefix(container_root) {
        return host_root.join(stripped);
    }
    path.to_path_buf()
}

fn map_request_args(args: &[String], container_root: &Path, host_root: &Path) -> Vec<String> {
    let mut mapped = Vec::with_capacity(args.len());
    let mut iter = args.iter().peekable();
    let mut options_done = false;

    while let Some(arg) = iter.next() {
        if options_done {
            mapped.push(arg.clone());
            continue;
        }

        if arg == "--" {
            options_done = true;
            mapped.push(arg.clone());
            continue;
        }

        if arg == "-C" || arg == "--directory" || arg == "-f" || arg == "--file" {
            mapped.push(arg.clone());
            if let Some(value) = iter.next() {
                mapped.push(map_container_arg(value, container_root, host_root));
            }
            continue;
        }

        if let Some(value) = arg.strip_prefix("-C") {
            if !value.is_empty() {
                let mapped_value = map_container_arg(value, container_root, host_root);
                mapped.push(format!("-C{mapped_value}"));
                continue;
            }
        }

        if let Some(value) = arg.strip_prefix("--directory=") {
            let mapped_value = map_container_arg(value, container_root, host_root);
            mapped.push(format!("--directory={mapped_value}"));
            continue;
        }

        if let Some(value) = arg.strip_prefix("-f") {
            if !value.is_empty() {
                let mapped_value = map_container_arg(value, container_root, host_root);
                mapped.push(format!("-f{mapped_value}"));
                continue;
            }
        }

        if let Some(value) = arg.strip_prefix("--file=") {
            let mapped_value = map_container_arg(value, container_root, host_root);
            mapped.push(format!("--file={mapped_value}"));
            continue;
        }

        mapped.push(arg.clone());
    }

    mapped
}

fn map_container_arg(value: &str, container_root: &Path, host_root: &Path) -> String {
    let path = Path::new(value);
    if path.is_absolute() {
        let mapped = map_container_path(path, container_root, host_root);
        return mapped.to_string_lossy().into_owned();
    }
    value.to_string()
}

fn run_build(
    mut writer: BufWriter<UnixStream>,
    _request: &Request,
    prepared: &PreparedRequest,
    config: &Config,
    user: &UserInfo,
    peer: &PeerIdentity,
) -> Result<(), RequestError> {
    let env = build_env(config, user);
    let uid = peer.uid;
    let gid = peer.gid;
    let groups: Vec<libc::gid_t> = peer.groups.iter().map(|gid| *gid as libc::gid_t).collect();

    let mut command = Command::new(&prepared.command_path);
    command
        .args(&prepared.args)
        .current_dir(&prepared.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();

    for (key, value) in env {
        command.env(key, value);
    }

    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            let groups_ptr = if groups.is_empty() {
                std::ptr::null()
            } else {
                groups.as_ptr()
            };
            if libc::setgroups(groups.len(), groups_ptr) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setgid(gid as libc::gid_t) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            send_error(&mut writer, &format!("failed to spawn build: {err}"));
            return Err(RequestError::Io(err));
        }
    };

    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let err = io::Error::other("failed to capture stdout");
            send_error(&mut writer, &err.to_string());
            return Err(RequestError::Io(err));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            let err = io::Error::other("failed to capture stderr");
            send_error(&mut writer, &err.to_string());
            return Err(RequestError::Io(err));
        }
    };

    let (tx, rx) = mpsc::channel();
    let writer_handle = thread::spawn(move || write_events(writer, rx));

    let stdout_handle = spawn_output_thread(stdout, tx.clone(), StreamKind::Stdout);
    let stderr_handle = spawn_output_thread(stderr, tx.clone(), StreamKind::Stderr);

    let start = Instant::now();
    let (exit_code, timed_out) = match wait_with_timeout(&mut child, prepared.timeout_sec) {
        Ok(result) => result,
        Err(err) => {
            let message = format!("wait failed: {err}");
            let _ = tx.send(ResponseEvent::Stderr { data: message });
            let _ = tx.send(ResponseEvent::Exit {
                code: 1,
                timed_out: false,
            });
            drop(tx);
            let _ = writer_handle.join();
            return Err(RequestError::Io(err));
        }
    };

    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    let _ = tx.send(ResponseEvent::Exit {
        code: exit_code,
        timed_out,
    });
    drop(tx);

    let _ = writer_handle.join();

    let duration = start.elapsed().as_secs();
    if timed_out {
        warn!(
            "build timed out user={} uid={} duration_sec={} cwd={}",
            user.username,
            peer.uid,
            duration,
            prepared.cwd.display()
        );
    } else {
        let level = if exit_code == 0 { "info" } else { "error" };
        if level == "info" {
            info!(
                "build completed user={} uid={} exit_code={} duration_sec={}",
                user.username, peer.uid, exit_code, duration
            );
        } else {
            error!(
                "build completed user={} uid={} exit_code={} duration_sec={}",
                user.username, peer.uid, exit_code, duration
            );
        }
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

                if sender.send(event).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn write_events(mut writer: BufWriter<UnixStream>, receiver: Receiver<ResponseEvent>) {
    for event in receiver {
        if write_event_line(&mut writer, &event).is_err() {
            break;
        }
    }
}

fn write_event_line(writer: &mut impl Write, event: &ResponseEvent) -> io::Result<()> {
    let line = serde_json::to_string(event).map_err(io::Error::other)?;
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn send_error(writer: &mut BufWriter<UnixStream>, message: &str) {
    let _ = write_event_line(
        writer,
        &ResponseEvent::Stderr {
            data: message.to_string(),
        },
    );
    let _ = write_event_line(
        writer,
        &ResponseEvent::Exit {
            code: 1,
            timed_out: false,
        },
    );
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

fn peer_cred(stream: &UnixStream) -> Result<PeerCred, RequestError> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(RequestError::Io(io::Error::last_os_error()));
    }

    Ok(PeerCred {
        uid: cred.uid,
        gid: cred.gid,
    })
}

fn peer_groups(stream: &UnixStream) -> io::Result<Vec<u32>> {
    let fd = stream.as_raw_fd();
    let max = unsafe { libc::sysconf(libc::_SC_NGROUPS_MAX) };
    let mut count = if max <= 0 { 32 } else { max as usize };
    if count == 0 {
        count = 32;
    }

    let mut groups: Vec<libc::gid_t> = vec![0; count];
    let mut len = (groups.len() * std::mem::size_of::<libc::gid_t>()) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERGROUPS,
            groups.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let count = len as usize / std::mem::size_of::<libc::gid_t>();
    groups.truncate(count);
    Ok(groups.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BuildConfig, LoggingConfig, ServiceConfig};
    use std::collections::HashMap;
    use std::process::ExitStatus;

    #[test]
    fn build_env_sets_user_values() {
        let mut build = BuildConfig::default();
        build.environment.allow = vec![
            "HOME".to_string(),
            "USER".to_string(),
            "LOGNAME".to_string(),
        ];

        let config = Config {
            schema_version: "1".to_string(),
            service: ServiceConfig::default(),
            build,
            logging: LoggingConfig::default(),
        };
        let user = UserInfo {
            username: "alice".to_string(),
            uid: 1000,
            gid: 1000,
            home_dir: PathBuf::from("/home/alice"),
        };

        let env = build_env(&config, &user);
        let map: HashMap<String, String> = env.into_iter().collect();

        assert_eq!(map.get("HOME").map(String::as_str), Some("/home/alice"));
        assert_eq!(map.get("USER").map(String::as_str), Some("alice"));
        assert_eq!(map.get("LOGNAME").map(String::as_str), Some("alice"));
    }

    #[test]
    fn exit_status_code_prefers_exit_code() {
        let status = ExitStatus::from_raw(7 << 8);
        assert_eq!(exit_status_code(status), 7);
    }

    #[test]
    fn exit_status_code_maps_signal() {
        let status = ExitStatus::from_raw(libc::SIGTERM);
        assert_eq!(exit_status_code(status), 128 + libc::SIGTERM);
    }
}
