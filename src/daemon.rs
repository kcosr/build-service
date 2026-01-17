use std::ffi::CString;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;

use tokio::sync::mpsc;
use tracing::warn;

use crate::build::{execute_build, validate_request, BuildError};
use crate::config::{Config, SocketModeError};
use crate::protocol::{Request, ResponseEvent};
use crate::user::{lookup_group_gid, UserError};

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

    #[error("missing request payload")]
    EmptyRequest,

    #[error("unauthorized")]
    Unauthorized,
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
    let socket_path = &config.service.socket.path;

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

    let gid = lookup_group_gid(&config.service.socket.group)?;
    apply_socket_permissions(socket_path, gid, config.service.socket.parse_mode()?)?;

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

    let request = match read_request(&mut reader) {
        Ok(request) => request,
        Err(err) => {
            send_error(&mut writer, err_code(&err), &err.to_string());
            return Err(err);
        }
    };

    if let Err(err) = authenticate_request(&request, &config) {
        send_error(&mut writer, err_code(&err), &err.to_string());
        return Err(err);
    }

    let validated = match validate_request(request, &config) {
        Ok(validated) => validated,
        Err(err) => {
            send_error_with_build(&mut writer, err);
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::channel::<ResponseEvent>(128);
    let writer_handle = thread::spawn(move || write_events(&mut writer, &mut rx));

    execute_build(validated, config, tx);
    let _ = writer_handle.join();

    Ok(())
}

fn authenticate_request(request: &Request, config: &Config) -> Result<(), RequestError> {
    if !config.service.socket.auth.required {
        return Ok(());
    }

    let token = request.auth_token.as_deref().unwrap_or("");
    if token.is_empty() {
        return Err(RequestError::Unauthorized);
    }

    if !config.service.socket.auth.tokens.iter().any(|t| t == token) {
        return Err(RequestError::Unauthorized);
    }

    Ok(())
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

fn write_events(writer: &mut BufWriter<UnixStream>, receiver: &mut mpsc::Receiver<ResponseEvent>) {
    while let Some(event) = receiver.blocking_recv() {
        if write_event_line(writer, &event).is_err() {
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

fn send_error(writer: &mut BufWriter<UnixStream>, code: &str, message: &str) {
    let _ = write_event_line(
        writer,
        &ResponseEvent::Error {
            code: code.to_string(),
            message: Some(message.to_string()),
            pattern: None,
        },
    );
    let _ = write_event_line(
        writer,
        &ResponseEvent::Exit {
            code: 1,
            timed_out: false,
            artifacts: None,
        },
    );
}

fn send_error_with_build(writer: &mut BufWriter<UnixStream>, err: BuildError) {
    let _ = write_event_line(
        writer,
        &ResponseEvent::Error {
            code: err.code.to_string(),
            message: Some(err.message),
            pattern: err.pattern,
        },
    );
    let _ = write_event_line(
        writer,
        &ResponseEvent::Exit {
            code: 1,
            timed_out: false,
            artifacts: None,
        },
    );
}

fn err_code(err: &RequestError) -> &'static str {
    match err {
        RequestError::Io(_) | RequestError::Json(_) | RequestError::EmptyRequest => {
            "invalid_request"
        }
        RequestError::Unauthorized => "unauthorized",
    }
}
