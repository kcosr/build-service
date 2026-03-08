use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::thread;

use tempfile::TempDir;

fn start_build_stream_server(body: String) -> (String, thread::JoinHandle<()>) {
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
            request_line.starts_with("POST /v1/builds HTTP/1.1"),
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

fn write_repo_config(
    repo_root: &Path,
    endpoint: &str,
    capture_logs: bool,
    log_dir: &str,
    stdout_max_lines: usize,
    stderr_max_lines: usize,
) {
    let config_dir = repo_root.join(".build-service");
    fs::create_dir_all(&config_dir).expect("create config dir");
    let config = format!(
        r#"[sources]
include = ["hello.txt"]

[artifacts]
include = ["out/**"]

[connection]
endpoint = "{endpoint}"

[output]
capture_logs = {capture_logs}
log_dir = "{log_dir}"
stdout_max_lines = {stdout_max_lines}
stderr_max_lines = {stderr_max_lines}
"#
    );
    fs::write(config_dir.join("config.toml"), config).expect("write config");
}

fn make_repo() -> TempDir {
    let temp = TempDir::new().expect("temp dir");
    fs::write(temp.path().join("hello.txt"), "hello\n").expect("write source");
    temp
}

fn run_build_cli(current_dir: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_build-cli"))
        .current_dir(current_dir)
        .env_remove("BUILD_SERVICE_ENABLED")
        .arg("make")
        .output()
        .expect("run build-cli")
}

#[test]
fn build_cli_uses_run_dir_for_relative_log_dir_and_reports_saved_logs() {
    let repo = make_repo();
    let nested = repo.path().join("nested");
    fs::create_dir_all(&nested).expect("create nested dir");

    let body = concat!(
        "{\"type\":\"stdout\",\"data\":\"pre-one\\npre-two\\n\"}\n",
        "{\"type\":\"build\",\"id\":\"bld_123\",\"status\":\"started\"}\n",
        "{\"type\":\"stderr\",\"data\":\"err-one\\nerr-two\\n\"}\n",
        "{\"type\":\"exit\",\"code\":0,\"timed_out\":false}\n"
    )
    .to_string();
    let (endpoint, handle) = start_build_stream_server(body);
    write_repo_config(repo.path(), &endpoint, true, "captured-logs", 1, 1);

    let output = run_build_cli(&nested);
    handle.join().expect("join server");

    assert_eq!(output.status.code(), Some(0));

    let stdout_path = nested.join("captured-logs/bld_123/stdout.log");
    let stderr_path = nested.join("captured-logs/bld_123/stderr.log");
    assert_eq!(
        fs::read_to_string(&stdout_path).expect("read stdout log"),
        "pre-one\npre-two\n"
    );
    assert_eq!(
        fs::read_to_string(&stderr_path).expect("read stderr log"),
        "err-one\nerr-two\n"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("pre-one\n"), "unexpected stdout: {stdout}");
    assert!(
        stdout.contains(&format!("full log: {}", stdout_path.display())),
        "unexpected stdout: {stdout}"
    );
    assert!(
        stderr.contains(&format!("full log: {}", stderr_path.display())),
        "unexpected stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "[build-service] saved full logs: stdout={}, stderr={}",
            stdout_path.display(),
            stderr_path.display()
        )),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn build_cli_warns_and_falls_back_when_build_event_is_missing() {
    let repo = make_repo();
    let body = concat!(
        "{\"type\":\"stdout\",\"data\":\"one\\ntwo\\n\"}\n",
        "{\"type\":\"exit\",\"code\":0,\"timed_out\":false}\n"
    )
    .to_string();
    let (endpoint, handle) = start_build_stream_server(body);
    write_repo_config(repo.path(), &endpoint, true, "captured-logs", 1, 1);

    let output = run_build_cli(repo.path());
    handle.join().expect("join server");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        !repo.path().join("captured-logs").exists(),
        "logs should not be created without a build event"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("BUILD_SERVICE_STDOUT_MAX_LINES=<lines>"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        stderr.contains(
            "log capture unavailable: build id was not received from the response stream"
        ),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !stderr.contains("saved full logs"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn build_cli_warns_and_falls_back_when_build_id_is_invalid() {
    let repo = make_repo();
    let body = concat!(
        "{\"type\":\"stdout\",\"data\":\"one\\ntwo\\n\"}\n",
        "{\"type\":\"build\",\"id\":\"../bad\",\"status\":\"started\"}\n",
        "{\"type\":\"exit\",\"code\":0,\"timed_out\":false}\n"
    )
    .to_string();
    let (endpoint, handle) = start_build_stream_server(body);
    write_repo_config(repo.path(), &endpoint, true, "captured-logs", 1, 1);

    let output = run_build_cli(repo.path());
    handle.join().expect("join server");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        !repo.path().join("captured-logs").exists(),
        "logs should not be created for invalid build ids"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("BUILD_SERVICE_STDOUT_MAX_LINES=<lines>"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        stderr.contains(
            "log capture unavailable: build id must not contain path separators or NUL bytes"
        ),
        "unexpected stderr: {stderr}"
    );
    assert!(
        !stderr.contains("saved full logs"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn build_cli_prints_completion_notice_without_suppression() {
    let repo = make_repo();
    let absolute_log_dir = repo.path().join("absolute-logs");
    let body = concat!(
        "{\"type\":\"build\",\"id\":\"bld_456\",\"status\":\"started\"}\n",
        "{\"type\":\"stdout\",\"data\":\"one\\n\"}\n",
        "{\"type\":\"stderr\",\"data\":\"err\\n\"}\n",
        "{\"type\":\"exit\",\"code\":0,\"timed_out\":false}\n"
    )
    .to_string();
    let (endpoint, handle) = start_build_stream_server(body);
    write_repo_config(
        repo.path(),
        &endpoint,
        true,
        absolute_log_dir.to_str().expect("absolute log dir"),
        50,
        50,
    );

    let output = run_build_cli(repo.path());
    handle.join().expect("join server");

    assert_eq!(output.status.code(), Some(0));

    let stdout_path = absolute_log_dir.join("bld_456/stdout.log");
    let stderr_path = absolute_log_dir.join("bld_456/stderr.log");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains("suppressing"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        !stderr.contains("suppressing"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "[build-service] saved full logs: stdout={}, stderr={}",
            stdout_path.display(),
            stderr_path.display()
        )),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn build_cli_disabled_capture_uses_env_hint_and_creates_no_logs() {
    let repo = make_repo();
    let body = concat!(
        "{\"type\":\"build\",\"id\":\"bld_789\",\"status\":\"started\"}\n",
        "{\"type\":\"stdout\",\"data\":\"one\\ntwo\\n\"}\n",
        "{\"type\":\"exit\",\"code\":0,\"timed_out\":false}\n"
    )
    .to_string();
    let (endpoint, handle) = start_build_stream_server(body);
    write_repo_config(repo.path(), &endpoint, false, "captured-logs", 1, 1);

    let output = run_build_cli(repo.path());
    handle.join().expect("join server");

    assert_eq!(output.status.code(), Some(0));
    assert!(
        !repo.path().join("captured-logs").exists(),
        "logs should not be created when capture is disabled"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("BUILD_SERVICE_STDOUT_MAX_LINES=<lines>"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        !stderr.contains("saved full logs"),
        "unexpected stderr: {stderr}"
    );
}
