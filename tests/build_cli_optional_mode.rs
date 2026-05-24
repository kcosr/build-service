use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

use tempfile::TempDir;

fn start_capture_server(body: String) -> (String, Arc<Mutex<Vec<u8>>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
    let addr = listener.local_addr().expect("server addr");
    let captured = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = Arc::clone(&captured);
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
            let mut request_body = vec![0; content_length];
            reader
                .read_exact(&mut request_body)
                .expect("read request body");
            *captured_clone.lock().expect("capture lock") = request_body;
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

    (format!("http://{addr}"), captured, handle)
}

#[test]
fn build_cli_runs_without_repo_config_and_omits_source_part() {
    let temp = TempDir::new().expect("temp dir");
    let response_body = concat!(
        "{\"type\":\"build\",\"id\":\"bld_123\",\"status\":\"started\"}\n",
        "{\"type\":\"exit\",\"code\":0,\"timed_out\":false}\n"
    )
    .to_string();
    let (endpoint, captured, handle) = start_capture_server(response_body);

    let output = Command::new(env!("CARGO_BIN_EXE_build-cli"))
        .current_dir(temp.path())
        .env_remove("BUILD_SERVICE_ENABLED")
        .env("BUILD_SERVICE_ENDPOINT", &endpoint)
        .arg("build")
        .arg("make")
        .output()
        .expect("run build-cli");
    handle.join().expect("join server");

    assert_eq!(output.status.code(), Some(0));

    let captured = captured.lock().expect("capture lock");
    let request_body = String::from_utf8_lossy(&captured);
    assert!(
        request_body.contains("name=\"metadata\""),
        "missing metadata part: {request_body}"
    );
    assert!(
        request_body.contains("\"command\":\"make\""),
        "missing metadata payload: {request_body}"
    );
    assert!(
        !request_body.contains("name=\"source\""),
        "unexpected source part: {request_body}"
    );
}
