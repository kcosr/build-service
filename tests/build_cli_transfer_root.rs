use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;
use zip::{write::FileOptions, ZipArchive, ZipWriter};

struct Upload {
    metadata: Value,
    files: BTreeMap<String, String>,
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                return stream;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "client did not contact mock server"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => panic!("accept request: {err}"),
        }
    }
}

fn request(stream: &TcpStream) -> (String, String, Vec<u8>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    let mut headers = String::new();
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().unwrap();
            }
        }
        headers.push_str(&line);
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    (first, headers, body)
}

fn respond(stream: &mut TcpStream, body: &[u8], content_type: &str) {
    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();
}

fn find(bytes: &[u8], needle: &[u8]) -> usize {
    bytes
        .windows(needle.len())
        .position(|part| part == needle)
        .expect("multipart delimiter")
}

fn multipart_part<'a>(body: &'a [u8], boundary: &str, name: &str) -> &'a [u8] {
    let marker = format!("name=\"{name}\"");
    let header = find(body, marker.as_bytes());
    let start = header + find(&body[header..], b"\r\n\r\n") + 4;
    let end = start + find(&body[start..], format!("\r\n--{boundary}").as_bytes());
    &body[start..end]
}

fn zip_files(bytes: &[u8]) -> BTreeMap<String, String> {
    let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
    (0..archive.len())
        .filter_map(|index| {
            let mut entry = archive.by_index(index).unwrap();
            if entry.is_dir() {
                return None;
            }
            let name = entry.name().to_owned();
            let mut contents = String::new();
            entry.read_to_string(&mut contents).unwrap();
            Some((name, contents))
        })
        .collect()
}

fn artifact_zip() -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (path, contents) in [
        ("consumer/out/result.txt", "build output"),
        ("shared/src/lib.rs", "formatted source"),
    ] {
        writer.start_file(path, FileOptions::default()).unwrap();
        writer.write_all(contents.as_bytes()).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn run(consumer: &Path, run_dir: &Path, extra_args: &[&str], artifacts: bool) -> Upload {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut stream = accept(&listener);
        let (first, headers, body) = request(&stream);
        assert!(first.starts_with("POST /v1/builds HTTP/1.1"));
        let boundary = headers
            .lines()
            .find_map(|line| line.split_once("boundary=").map(|(_, value)| value.trim()))
            .unwrap();
        let upload = Upload {
            metadata: serde_json::from_slice(multipart_part(&body, boundary, "metadata")).unwrap(),
            files: zip_files(multipart_part(&body, boundary, "source")),
        };
        let archive = artifact_zip();
        let mut exit = serde_json::json!({"type":"exit", "code":0, "timed_out":false});
        if artifacts {
            exit["artifacts"] =
                serde_json::json!({"path":"/v1/builds/test/artifacts", "size":archive.len()});
        }
        respond(
            &mut stream,
            format!("{exit}\n").as_bytes(),
            "application/x-ndjson",
        );
        if artifacts {
            let mut stream = accept(&listener);
            let (first, _, _) = request(&stream);
            assert!(first.starts_with("GET /v1/builds/test/artifacts HTTP/1.1"));
            respond(&mut stream, &archive, "application/zip");
        }
        upload
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_build-cli"));
    for (name, _) in std::env::vars() {
        if name.starts_with("BUILD_SERVICE_") {
            command.env_remove(name);
        }
    }
    let output = command
        .current_dir(run_dir)
        .args(["--endpoint", &endpoint, "build"])
        .args(extra_args)
        .arg("make")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "consumer {}: {}",
        consumer.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    server.join().expect("mock server")
}

fn layout(root: &Path, consumer: &str) {
    let repo = root.join(consumer);
    fs::create_dir_all(repo.join(".build-service")).unwrap();
    fs::create_dir_all(repo.join("nested")).unwrap();
    fs::create_dir_all(repo.join("src/config/target")).unwrap();
    fs::create_dir_all(repo.join("target/debug")).unwrap();
    fs::write(repo.join("src/config/target/mod.rs"), "real module").unwrap();
    fs::write(repo.join("target/debug/generated.rs"), "build output").unwrap();
    fs::write(repo.join(".git"), "gitdir: /not-uploaded/worktree").unwrap();
    fs::create_dir_all(root.join("shared/src")).unwrap();
    fs::write(repo.join("main.rs"), "consumer source").unwrap();
    fs::write(root.join("shared/src/lib.rs"), "shared source").unwrap();
    fs::write(
        repo.join(".build-service/config.toml"),
        format!(
            r#"[sources]
root = ".."
include = ["{consumer}/**", "shared/src/**"]
exclude = ["{consumer}/target/**", "{consumer}/.build-service/**", "{consumer}/.git", "{consumer}/.git/**"]
[artifacts]
include = ["{consumer}/out/**", "shared/src/**"]
[workspace]
reuse = true
"#
        ),
    )
    .unwrap();
}

#[test]
fn sibling_sources_and_artifacts_use_transfer_root_from_nested_consumer() {
    let temp = TempDir::new().unwrap();
    layout(temp.path(), "consumer");
    let consumer = temp.path().join("consumer");
    let upload = run(&consumer, &consumer.join("nested"), &[], true);
    assert_eq!(upload.metadata["cwd"], "consumer/nested");
    assert_eq!(
        upload.files,
        BTreeMap::from([
            ("consumer/main.rs".into(), "consumer source".into()),
            (
                "consumer/src/config/target/mod.rs".into(),
                "real module".into()
            ),
            ("shared/src/lib.rs".into(), "shared source".into()),
        ])
    );
    assert_eq!(
        fs::read_to_string(consumer.join("out/result.txt")).unwrap(),
        "build output"
    );
    assert_eq!(
        fs::read_to_string(temp.path().join("shared/src/lib.rs")).unwrap(),
        "formatted source"
    );
    assert!(!consumer.join("shared").exists());
}

#[test]
fn explicit_cwd_is_relative_to_transfer_root() {
    let temp = TempDir::new().unwrap();
    layout(temp.path(), "consumer");
    let consumer = temp.path().join("consumer");
    let upload = run(
        &consumer,
        &consumer.join("nested"),
        &["--cwd", "shared"],
        false,
    );
    assert_eq!(upload.metadata["cwd"], "shared");
}

#[test]
fn configured_cwd_is_relative_to_transfer_root() {
    let temp = TempDir::new().unwrap();
    layout(temp.path(), "consumer");
    let consumer = temp.path().join("consumer");
    let config_path = consumer.join(".build-service/config.toml");
    let config = fs::read_to_string(&config_path).unwrap();
    fs::write(
        config_path,
        format!("{config}\n[request]\ncwd = \"shared\"\n"),
    )
    .unwrap();
    let upload = run(&consumer, &consumer.join("nested"), &[], false);
    assert_eq!(upload.metadata["cwd"], "shared");
}

#[test]
fn default_workspace_identity_is_stable_and_isolates_feature_roots_and_consumers() {
    let first = TempDir::new().unwrap();
    let second = TempDir::new().unwrap();
    layout(first.path(), "consumer");
    layout(first.path(), "other-consumer");
    layout(second.path(), "consumer");
    let consumer = first.path().join("consumer");
    let initial = run(&consumer, &consumer, &[], false).metadata["workspace"]["id"].clone();
    assert!(initial.as_str().is_some_and(|value| !value.is_empty()));
    let nested =
        run(&consumer, &consumer.join("nested"), &[], false).metadata["workspace"]["id"].clone();
    assert_eq!(initial, nested);
    let other = first.path().join("other-consumer");
    let other_id = run(&other, &other, &[], false).metadata["workspace"]["id"].clone();
    assert_ne!(initial, other_id);
    let separate = second.path().join("consumer");
    let separate_id = run(&separate, &separate, &[], false).metadata["workspace"]["id"].clone();
    assert_ne!(initial, separate_id);
}
