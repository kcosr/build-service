#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use reqwest::blocking::{multipart, Client};
use serde_json::{json, Value};
use tempfile::TempDir;

const COMMAND_STDOUT: &str = "command stdout\n";
const COMMAND_STDERR: &str = "command stderr\n";

struct Process(Option<Child>);

impl Process {
    fn spawn(mut command: Command) -> Self {
        Self(Some(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn process"),
        ))
    }

    fn output(mut self) -> Output {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "process did not finish");
            thread::sleep(Duration::from_millis(10));
        }
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn command(binary: &str) -> Command {
    let mut command = Command::new(binary);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("BUILD_SERVICE_") {
            command.env_remove(key);
        }
    }
    command.env("TOKIO_WORKER_THREADS", "2");
    command
}

struct TestServer {
    _process: Process,
    temp: TempDir,
    socket: PathBuf,
    client_dir: PathBuf,
}

impl TestServer {
    fn start(stdout_notice: Option<&str>, stderr_notice: Option<&str>) -> Self {
        let temp = TempDir::new().expect("temp dir");
        let socket = temp.path().join("service.sock");
        let workspace = temp.path().join("workspace");
        let client_dir = temp.path().join("client");
        fs::create_dir(&workspace).unwrap();
        fs::create_dir(&client_dir).unwrap();
        let script = temp.path().join("build.sh");
        fs::write(
            &script,
            "#!/bin/sh\nprintf 'command stdout\\n'\nprintf 'command stderr\\n' >&2\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

        let quote = |value: &str| toml::Value::String(value.to_owned()).to_string();
        let mut config = format!(
            "[service.socket]\npath = {}\n\
             [service.http]\nenabled = false\n\
             [build]\nworkspace_root = {}\ndefault_workspace_path = {}\n\
             [build.commands]\ntest = {}\n\
             [build.timeouts]\ndefault_sec = 5\nmax_sec = 5\n\
             [artifacts]\nstorage_root = {}\n\
             [logging]\nconsole = false\n",
            quote(socket.to_str().unwrap()),
            quote(temp.path().join("workspaces").to_str().unwrap()),
            quote(workspace.to_str().unwrap()),
            quote(script.to_str().unwrap()),
            quote(temp.path().join("artifacts").to_str().unwrap()),
        );
        if stdout_notice.is_some() || stderr_notice.is_some() {
            config.push_str("[build.output]\n");
            for (key, notice) in [
                ("stdout_notice", stdout_notice),
                ("stderr_notice", stderr_notice),
            ] {
                if let Some(notice) = notice {
                    config.push_str(&format!("{key} = {}\n", quote(notice)));
                }
            }
        }
        let config_path = temp.path().join("server.toml");
        fs::write(&config_path, config).unwrap();
        let mut server_command = command(env!("CARGO_BIN_EXE_build-service"));
        server_command.arg("--config").arg(config_path);
        let mut process = Process::spawn(server_command);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if UnixStream::connect(&socket).is_ok() {
                break;
            }
            if process.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                panic!("server exited before startup: {:?}", process.output());
            }
            assert!(
                Instant::now() < deadline,
                "server did not create its socket"
            );
            thread::sleep(Duration::from_millis(10));
        }
        Self {
            _process: process,
            temp,
            socket,
            client_dir,
        }
    }

    fn events(&self) -> Vec<Value> {
        let response = Client::builder()
            .unix_socket(self.socket.clone())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
            .post("http://localhost/v1/builds")
            .multipart(multipart::Form::new().text("metadata", r#"{"command":"test"}"#))
            .send()
            .unwrap()
            .error_for_status()
            .unwrap();
        let mut events = Vec::new();
        for line in BufReader::new(response).lines() {
            let event: Value = serde_json::from_str(&line.unwrap()).unwrap();
            let finished = event["type"] == "exit";
            events.push(event);
            if finished {
                return events;
            }
        }
        panic!("response ended without an exit event");
    }

    fn run_cli(&self, args: &[&str]) -> Output {
        let mut cli = command(env!("CARGO_BIN_EXE_build-cli"));
        cli.current_dir(&self.client_dir)
            .arg("--endpoint")
            .arg(format!("unix://{}", self.socket.display()))
            .arg("build")
            .args(args)
            .arg("test");
        Process::spawn(cli).output()
    }
}

fn streams(output: &Output) -> (&str, &str) {
    (
        std::str::from_utf8(&output.stdout).unwrap(),
        std::str::from_utf8(&output.stderr).unwrap(),
    )
}

fn event_data(events: &[Value], stream: &str) -> String {
    events
        .iter()
        .filter(|event| event["type"] == stream)
        .map(|event| event["data"].as_str().unwrap())
        .collect()
}

#[test]
fn default_and_empty_notices_leave_command_output_unchanged() {
    for notices in [(None, None), (Some(""), Some(""))] {
        let server = TestServer::start(notices.0, notices.1);
        let events = server.events();
        assert_eq!(events[0]["type"], "build");
        assert_eq!(events.last().unwrap()["type"], "exit");
        assert_eq!(events.last().unwrap()["code"], 0);
        assert_eq!(event_data(&events, "stdout"), COMMAND_STDOUT);
        assert_eq!(event_data(&events, "stderr"), COMMAND_STDERR);
        let output = server.run_cli(&[]);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(streams(&output), (COMMAND_STDOUT, COMMAND_STDERR));
    }
}

#[test]
fn notices_preserve_text_and_precede_command_output_in_each_stream() {
    let server = TestServer::start(Some(" first line\nsecond line "), Some("stderr notice\n\n"));
    let stdout = " first line\nsecond line \n";
    let stderr = "stderr notice\n\n";
    let events = server.events();
    assert_eq!(events[0]["type"], "build");
    assert_eq!(events[0]["status"], "started");
    assert_eq!(events[1], json!({"type": "stdout", "data": stdout}));
    assert_eq!(events[2], json!({"type": "stderr", "data": stderr}));
    assert_eq!(events.last().unwrap()["type"], "exit");
    assert_eq!(events.last().unwrap()["code"], 0);
    assert_eq!(
        event_data(&events, "stdout"),
        format!("{stdout}{COMMAND_STDOUT}")
    );
    assert_eq!(
        event_data(&events, "stderr"),
        format!("{stderr}{COMMAND_STDERR}")
    );
    let output = server.run_cli(&[]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(streams(&output).0, format!("{stdout}{COMMAND_STDOUT}"));
    assert_eq!(streams(&output).1, format!("{stderr}{COMMAND_STDERR}"));
}

#[test]
fn stdout_and_stderr_notices_can_be_configured_independently() {
    for (stdout_notice, stderr_notice, expected_stdout, expected_stderr) in [
        (
            Some("stdout only"),
            None,
            "stdout only\ncommand stdout\n",
            COMMAND_STDERR,
        ),
        (
            None,
            Some("stderr only"),
            COMMAND_STDOUT,
            "stderr only\ncommand stderr\n",
        ),
    ] {
        let server = TestServer::start(stdout_notice, stderr_notice);
        let output = server.run_cli(&[]);
        assert!(output.status.success(), "{output:?}");
        assert_eq!(streams(&output), (expected_stdout, expected_stderr));
    }
}

#[test]
fn full_log_capture_preserves_notices_when_terminal_output_is_suppressed() {
    let server = TestServer::start(Some("stdout notice"), Some("stderr notice"));
    let config_dir = server.client_dir.join(".build-service");
    fs::create_dir(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[output]\ncapture_logs = true\nlog_dir = 'logs'\n\
         stdout_max_lines = 0\nstderr_max_lines = 0\n\
         stdout_tail_lines = 0\nstderr_tail_lines = 0\n",
    )
    .unwrap();
    let output = server.run_cli(&[]);
    assert!(output.status.success(), "{output:?}");
    let (stdout, stderr) = streams(&output);
    assert!(stdout.contains("suppressing stdout output"), "{stdout}");
    assert!(stderr.contains("suppressing stderr output"), "{stderr}");
    assert!(!stdout.contains("stdout notice"));
    assert!(!stderr.contains("stderr notice"));
    assert!(!stdout.contains(COMMAND_STDOUT));
    assert!(!stderr.contains(COMMAND_STDERR));
    let logs: Vec<_> = fs::read_dir(server.client_dir.join("logs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(logs.len(), 1);
    assert_eq!(
        fs::read_to_string(logs[0].join("stdout.log")).unwrap(),
        "stdout notice\ncommand stdout\n"
    );
    assert_eq!(
        fs::read_to_string(logs[0].join("stderr.log")).unwrap(),
        "stderr notice\ncommand stderr\n"
    );
    assert!(stderr.contains("saved full logs:"), "{stderr}");
}

#[test]
fn notices_are_emitted_before_an_accepted_build_fails_during_setup() {
    let server = TestServer::start(Some("stdout notice"), Some("stderr notice"));
    let output = server.run_cli(&["--cwd", "missing-directory"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let (stdout, stderr) = streams(&output);
    assert_eq!(stdout, "stdout notice\n");
    assert!(stderr.starts_with("stderr notice\n"), "{stderr}");
    assert!(stderr.contains("invalid path for cwd:"), "{stderr}");
    assert!(!stderr.contains(COMMAND_STDERR));
    assert!(!server
        .temp
        .path()
        .join("workspace/missing-directory")
        .exists());
}
