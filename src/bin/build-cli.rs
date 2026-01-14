use std::env;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use build_service::protocol::{Request, ResponseEvent, SCHEMA_VERSION};

const DEFAULT_SOCKET_PATH: &str = "/run/build-service.sock";

#[derive(Debug, Parser)]
#[command(author, version, about = "Client for the build-service daemon")]
struct Args {
    #[arg(long)]
    timeout: Option<u64>,

    #[arg(long)]
    socket: Option<PathBuf>,

    #[arg(long)]
    request_id: Option<String>,

    #[arg(required = true)]
    command: String,

    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let cwd = match env::current_dir() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("failed to resolve cwd: {err}");
            return ExitCode::from(1);
        }
    };

    let socket_path = resolve_socket_path(args.socket);
    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(stream) => stream,
        Err(err) => {
            let message = match err.kind() {
                io::ErrorKind::NotFound => {
                    format!(
                        "build-service socket not found at {}",
                        socket_path.display()
                    )
                }
                io::ErrorKind::ConnectionRefused => "cannot connect to build-service".to_string(),
                _ => format!("cannot connect to build-service: {err}"),
            };
            eprintln!("{message}");
            return ExitCode::from(1);
        }
    };

    let request = Request {
        schema_version: Some(SCHEMA_VERSION.to_string()),
        request_id: args.request_id,
        command: args.command,
        args: args.args,
        cwd: cwd.to_string_lossy().into_owned(),
        timeout_sec: args.timeout,
    };

    if let Err(err) = send_request(&mut stream, &request) {
        eprintln!("failed to send request: {err}");
        return ExitCode::from(1);
    }

    match read_responses(stream) {
        Ok(code) => to_exit_code(code),
        Err(err) => {
            eprintln!("invalid response from build-service: {err}");
            ExitCode::from(1)
        }
    }
}

fn resolve_socket_path(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(path) = explicit {
        return path;
    }

    if let Ok(env_path) = env::var("BUILD_SERVICE_SOCKET") {
        if !env_path.trim().is_empty() {
            return PathBuf::from(env_path);
        }
    }

    PathBuf::from(DEFAULT_SOCKET_PATH)
}

fn send_request(stream: &mut UnixStream, request: &Request) -> io::Result<()> {
    let payload = serde_json::to_vec(request).map_err(io::Error::other)?;
    stream.write_all(&payload)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn read_responses(stream: UnixStream) -> io::Result<i32> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let mut exit_code: Option<i32> = None;

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
            ResponseEvent::Exit { code, timed_out } => {
                exit_code = Some(if timed_out { 124 } else { code });
                break;
            }
        }
    }

    match exit_code {
        Some(code) => Ok(code),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing exit event",
        )),
    }
}

fn to_exit_code(code: i32) -> ExitCode {
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
    use std::io::Write;
    use std::sync::Mutex;
    use std::thread;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn normalize_exit_code_clamps() {
        assert_eq!(normalize_exit_code(-1), 1);
        assert_eq!(normalize_exit_code(0), 0);
        assert_eq!(normalize_exit_code(255), 255);
        assert_eq!(normalize_exit_code(300), 255);
    }

    #[test]
    fn resolve_socket_path_prefers_explicit() {
        let path = resolve_socket_path(Some(PathBuf::from("/tmp/explicit.sock")));
        assert_eq!(path, PathBuf::from("/tmp/explicit.sock"));
    }

    #[test]
    fn resolve_socket_path_uses_env() {
        let _guard = ENV_LOCK.lock().expect("lock");
        env::set_var("BUILD_SERVICE_SOCKET", "/tmp/env.sock");
        let path = resolve_socket_path(None);
        env::remove_var("BUILD_SERVICE_SOCKET");
        assert_eq!(path, PathBuf::from("/tmp/env.sock"));
    }

    #[test]
    fn resolve_socket_path_defaults_when_env_empty() {
        let _guard = ENV_LOCK.lock().expect("lock");
        env::set_var("BUILD_SERVICE_SOCKET", " ");
        let path = resolve_socket_path(None);
        env::remove_var("BUILD_SERVICE_SOCKET");
        assert_eq!(path, PathBuf::from(DEFAULT_SOCKET_PATH));
    }

    #[test]
    fn read_responses_returns_exit_code() {
        let (client, mut server) = UnixStream::pair().expect("pair");
        let handle = thread::spawn(move || {
            let event = ResponseEvent::Exit {
                code: 7,
                timed_out: false,
            };
            let line = serde_json::to_string(&event).expect("json");
            server.write_all(line.as_bytes()).expect("write");
            server.write_all(b"\n").expect("newline");
        });

        let code = read_responses(client).expect("read");
        assert_eq!(code, 7);
        handle.join().expect("join");
    }

    #[test]
    fn read_responses_timeout_overrides_code() {
        let (client, mut server) = UnixStream::pair().expect("pair");
        let handle = thread::spawn(move || {
            let event = ResponseEvent::Exit {
                code: 2,
                timed_out: true,
            };
            let line = serde_json::to_string(&event).expect("json");
            server.write_all(line.as_bytes()).expect("write");
            server.write_all(b"\n").expect("newline");
        });

        let code = read_responses(client).expect("read");
        assert_eq!(code, 124);
        handle.join().expect("join");
    }
}
