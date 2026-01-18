use std::ffi::CString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Multipart, Path as AxumPath, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tokio_util::io::ReaderStream;
use tracing::{error, warn};

use crate::build::{execute_build, validate_request};
use crate::config::{Config, HttpAuthConfig, SocketModeError};
use crate::protocol::Request;
use crate::user::UserError;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("http server failed: {0}")]
    Serve(String),

    #[error("tls configuration error: {0}")]
    Tls(String),

    #[error("invalid socket mode: {0}")]
    SocketMode(#[from] SocketModeError),

    #[error("group lookup failed: {0}")]
    GroupLookup(#[from] UserError),
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    auth_required: bool,
}

#[derive(serde::Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn run(config: Arc<Config>) -> Result<(), HttpError> {
    match (config.service.http.enabled, config.service.socket.enabled) {
        (true, true) => {
            let tcp = run_tcp(Arc::clone(&config));
            let uds = run_uds(Arc::clone(&config));
            tokio::try_join!(tcp, uds)?;
        }
        (true, false) => {
            run_tcp(config).await?;
        }
        (false, true) => {
            run_uds(config).await?;
        }
        (false, false) => {}
    }

    Ok(())
}

async fn run_tcp(config: Arc<Config>) -> Result<(), HttpError> {
    let addr: std::net::SocketAddr = config
        .service
        .http
        .listen_addr
        .parse()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let state = AppState {
        config: Arc::clone(&config),
        auth_required: config.service.http.auth.required,
    };
    let app = build_router(state, config.build.max_upload_bytes);

    if config.service.http.tls.enabled {
        let tls_config = build_tls_config(config.as_ref())?;
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
            .map_err(|err| HttpError::Serve(err.to_string()))?;
    } else {
        axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .map_err(|err| HttpError::Serve(err.to_string()))?;
    }

    Ok(())
}

async fn run_uds(config: Arc<Config>) -> Result<(), HttpError> {
    let listener = setup_socket(&config)?;
    let state = AppState {
        config: Arc::clone(&config),
        auth_required: false,
    };
    let app = build_router(state, config.build.max_upload_bytes);

    loop {
        let (stream, _) = listener.accept().await?;
        let service = TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                warn!("uds connection failed: {err}");
            }
        });
    }
}

fn build_router(state: AppState, max_upload_bytes: u64) -> Router {
    let max_body = max_upload_bytes.saturating_add(1024 * 1024) as usize;
    Router::new()
        .route("/v1/builds", post(start_build))
        .route("/v1/builds/:build_id/artifacts.zip", get(get_artifact))
        .with_state(state)
        .layer(DefaultBodyLimit::max(max_body))
}

async fn start_build(
    State(state): State<AppState>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> Response {
    if let Some(response) = authorize(
        &headers,
        &state.config.service.http.auth,
        state.auth_required,
    ) {
        return response;
    }

    let mut metadata: Option<Request> = None;
    let mut source_path: Option<std::path::PathBuf> = None;
    let mut source_bytes = 0u64;

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(err) => return bad_request(&format!("invalid multipart body: {err}")),
        };
        let mut field = field;
        let name = field.name().unwrap_or("").to_string();

        if name == "metadata" {
            if metadata.is_some() {
                return bad_request("duplicate metadata field");
            }

            let data = match field.bytes().await {
                Ok(data) => data,
                Err(err) => return bad_request(&format!("failed to read metadata: {err}")),
            };
            let parsed: Request = match serde_json::from_slice(&data) {
                Ok(parsed) => parsed,
                Err(err) => return bad_request(&format!("invalid metadata json: {err}")),
            };
            metadata = Some(parsed);
            continue;
        }

        if name == "source" {
            if source_path.is_some() {
                return bad_request("duplicate source field");
            }

            if let Err(err) = std::fs::create_dir_all(&state.config.build.workspace_root) {
                return server_error(&format!("failed to create workspace root: {err}"));
            }

            let mut temp = match tempfile::Builder::new()
                .prefix("build-service-src-")
                .suffix(".zip")
                .tempfile_in(&state.config.build.workspace_root)
            {
                Ok(temp) => temp,
                Err(err) => return server_error(&format!("failed to create temp file: {err}")),
            };

            loop {
                match field.chunk().await {
                    Ok(Some(chunk)) => {
                        source_bytes = source_bytes.saturating_add(chunk.len() as u64);
                        if source_bytes > state.config.build.max_upload_bytes {
                            return payload_too_large("source archive exceeds max_upload_bytes");
                        }
                        if let Err(err) = temp.write_all(&chunk) {
                            return server_error(&format!("failed to write source: {err}"));
                        }
                    }
                    Ok(None) => break,
                    Err(err) => return bad_request(&format!("failed to read source: {err}")),
                }
            }

            let temp_path = temp.into_temp_path();
            match temp_path.keep() {
                Ok(path) => {
                    source_path = Some(path);
                }
                Err(err) => {
                    return server_error(&format!("failed to persist source: {err}"));
                }
            }

            continue;
        }
    }

    let request = match metadata {
        Some(request) => request,
        None => {
            if let Some(path) = &source_path {
                let _ = std::fs::remove_file(path);
            }
            return bad_request("missing metadata field");
        }
    };

    let source = match source_path {
        Some(path) => path,
        None => return bad_request("missing source field"),
    };

    let validated = match validate_request(request, &state.config) {
        Ok(validated) => validated,
        Err(err) => {
            let _ = std::fs::remove_file(&source);
            let body = Json(ErrorResponse { error: err.message });
            return (StatusCode::BAD_REQUEST, body).into_response();
        }
    };

    let (tx, rx) = mpsc::channel(128);
    let config = Arc::clone(&state.config);
    tokio::task::spawn_blocking(move || execute_build(validated, config, source, tx));

    let stream = ReceiverStream::new(rx).map(|event| {
        let line = match serde_json::to_string(&event) {
            Ok(json) => json,
            Err(err) => {
                format!("{{\"type\":\"error\",\"code\":\"serialization\",\"message\":\"{err}\"}}")
            }
        };
        Ok::<Bytes, std::convert::Infallible>(Bytes::from(format!("{line}\n")))
    });

    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response
}

async fn get_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(build_id): AxumPath<String>,
) -> Response {
    if let Some(response) = authorize(
        &headers,
        &state.config.service.http.auth,
        state.auth_required,
    ) {
        return response;
    }

    let root = state.config.artifacts.storage_root.join(&build_id);
    let candidate = root.join("artifacts.zip");

    let resolved_root = match std::fs::canonicalize(&root) {
        Ok(path) => path,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let resolved = match std::fs::canonicalize(&candidate) {
        Ok(path) => path,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    if !resolved.starts_with(&resolved_root) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let file = match tokio::fs::File::open(&resolved).await {
        Ok(file) => file,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let stream = ReaderStream::new(file);
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    response
}

fn authorize(headers: &HeaderMap, auth: &HttpAuthConfig, enforce: bool) -> Option<Response> {
    if !enforce {
        return None;
    }

    let header_value = match headers.get(header::AUTHORIZATION) {
        Some(value) => value.to_str().ok(),
        None => None,
    };

    let token = header_value
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");

    if token.is_empty() || !auth.tokens.iter().any(|t| t == token) {
        let body = Json(ErrorResponse {
            error: "unauthorized".to_string(),
        });
        return Some((StatusCode::UNAUTHORIZED, body).into_response());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ArtifactsConfig, BuildConfig, Config, LoggingConfig, ServiceConfig};
    use crate::protocol::{ArtifactSpec, Request, ResponseEvent, SCHEMA_VERSION};
    use reqwest::blocking::multipart::{Form, Part};
    use reqwest::blocking::Client;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Cursor, Read, Write};
    use std::net::SocketAddr;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::{tempdir, NamedTempFile, TempDir};
    use zip::write::FileOptions;
    use zip::ZipWriter;

    enum Transport {
        Http { base_url: String },
        Unix { socket_path: PathBuf },
    }

    struct TestEnv {
        temp: TempDir,
        app: Router,
    }

    #[tokio::test]
    async fn http_build_returns_artifacts_zip() {
        let env = setup_env();
        let (addr, server_handle) = start_http_server(env.app).await;
        let transport = Transport::Http {
            base_url: format!("http://{addr}"),
        };

        let zip_bytes = run_build_and_fetch(transport).await;
        assert_zip_contains(&zip_bytes, "out/hello.txt", "hello");

        server_handle.abort();
    }

    #[tokio::test]
    async fn uds_build_returns_artifacts_zip() {
        let env = setup_env();
        let socket_path = env.temp.path().join("build-service.sock");
        let server_handle = start_uds_server(env.app, &socket_path).await;
        let transport = Transport::Unix { socket_path };

        let zip_bytes = run_build_and_fetch(transport).await;
        assert_zip_contains(&zip_bytes, "out/hello.txt", "hello");

        server_handle.abort();
    }

    fn setup_env() -> TestEnv {
        let temp = tempdir().expect("tempdir");
        let workspace_root = temp.path().join("workspace");
        let artifacts_root = temp.path().join("artifacts");
        let bin_dir = temp.path().join("bin");
        std::fs::create_dir_all(&workspace_root).expect("workspace root");
        std::fs::create_dir_all(&artifacts_root).expect("artifacts root");
        std::fs::create_dir_all(&bin_dir).expect("bin dir");

        let script_path = bin_dir.join("build.sh");
        std::fs::write(
            &script_path,
            "#!/bin/sh\nmkdir -p out\necho hello > out/hello.txt\n",
        )
        .expect("write script");
        let mut perms = std::fs::metadata(&script_path)
            .expect("stat script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).expect("chmod");

        let mut config = Config {
            schema_version: "3".to_string(),
            service: ServiceConfig::default(),
            build: BuildConfig::default(),
            artifacts: ArtifactsConfig::default(),
            logging: LoggingConfig::default(),
        };
        config.build.workspace_root = workspace_root.clone();
        config
            .build
            .commands
            .insert("build".to_string(), script_path);
        config.artifacts.storage_root = artifacts_root;

        let app = build_app(config);
        TestEnv { temp, app }
    }

    fn build_app(config: Config) -> Router {
        let max_upload_bytes = config.build.max_upload_bytes;
        let state = AppState {
            config: Arc::new(config),
            auth_required: false,
        };
        build_router(state, max_upload_bytes)
    }

    async fn start_http_server(app: Router) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let addr = listener.local_addr().expect("addr");
        let server = axum_server::from_tcp(listener)
            .expect("server")
            .serve(app.into_make_service());
        let handle = tokio::spawn(async move {
            let _ = server.await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        (addr, handle)
    }

    async fn start_uds_server(app: Router, socket_path: &Path) -> tokio::task::JoinHandle<()> {
        if socket_path.exists() {
            std::fs::remove_file(socket_path).expect("remove socket");
        }
        let listener = UnixListener::bind(socket_path).expect("bind uds");
        let handle = tokio::spawn({
            let app = app.clone();
            async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    let service = TowerToHyperService::new(app.clone());
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let _ = http1::Builder::new().serve_connection(io, service).await;
                    });
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        handle
    }

    async fn run_build_and_fetch(transport: Transport) -> Vec<u8> {
        tokio::task::spawn_blocking(move || {
            let source_archive = create_source_zip().expect("source zip");
            let request = build_request();
            let (client, base_url) = build_client(&transport);
            let archive_path = post_build(&client, &base_url, &request, &source_archive);
            fetch_zip(&client, &base_url, &archive_path)
        })
        .await
        .expect("build task")
    }

    fn build_client(transport: &Transport) -> (Client, String) {
        match transport {
            Transport::Http { base_url } => (Client::new(), base_url.clone()),
            Transport::Unix { socket_path } => (
                Client::builder()
                    .unix_socket(socket_path.clone())
                    .build()
                    .expect("client"),
                "http://localhost".to_string(),
            ),
        }
    }

    fn post_build(
        client: &Client,
        base_url: &str,
        request: &Request,
        source_archive: &NamedTempFile,
    ) -> String {
        let metadata = serde_json::to_string(request).expect("metadata");
        let form = Form::new()
            .part(
                "metadata",
                Part::text(metadata)
                    .mime_str("application/json")
                    .expect("metadata mime"),
            )
            .part(
                "source",
                Part::file(source_archive.path())
                    .expect("source part")
                    .mime_str("application/zip")
                    .expect("source mime"),
            );

        let base = base_url.trim_end_matches('/');
        let url = format!("{base}/v1/builds");
        let response = client.post(url).multipart(form).send().expect("send");
        assert!(response.status().is_success());

        let mut reader = BufReader::new(response);
        let mut line = String::new();
        let mut artifacts = None;
        loop {
            line.clear();
            let bytes = reader.read_line(&mut line).expect("read line");
            if bytes == 0 {
                break;
            }
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            let event: ResponseEvent = serde_json::from_str(trimmed).expect("event parse");
            if let ResponseEvent::Exit {
                artifacts: exit, ..
            } = event
            {
                artifacts = exit;
                break;
            }
        }
        let archive = artifacts.expect("missing artifacts");
        archive.path
    }

    fn fetch_zip(client: &Client, base_url: &str, archive_path: &str) -> Vec<u8> {
        let base = base_url.trim_end_matches('/');
        let url = format!("{base}{archive_path}");
        let mut response = client.get(url).send().expect("get");
        assert!(response.status().is_success());
        let mut buf = Vec::new();
        response.copy_to(&mut buf).expect("read zip");
        buf
    }

    fn build_request() -> Request {
        Request {
            schema_version: Some(SCHEMA_VERSION.to_string()),
            request_id: Some("test".to_string()),
            command: "build".to_string(),
            args: Vec::new(),
            cwd: None,
            timeout_sec: Some(60),
            artifacts: ArtifactSpec {
                include: vec!["out/**".to_string()],
                exclude: Vec::new(),
            },
            env: Some(HashMap::new()),
        }
    }

    fn assert_zip_contains(zip_bytes: &[u8], name: &str, expected: &str) {
        let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes)).expect("zip");
        let mut file = archive.by_name(name).expect("zip entry");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("read entry");
        assert_eq!(contents.trim(), expected);
    }

    fn create_source_zip() -> std::io::Result<NamedTempFile> {
        let temp = tempfile::Builder::new()
            .prefix("build-service-test-src-")
            .suffix(".zip")
            .tempfile()?;
        let file = temp.reopen()?;
        let mut zip = ZipWriter::new(file);
        let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("input.txt", options)?;
        zip.write_all(b"source")?;
        zip.finish()?;
        Ok(temp)
    }
}

fn setup_socket(config: &Config) -> Result<UnixListener, HttpError> {
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

    let gid = crate::user::lookup_group_gid(&config.service.socket.group)?;
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

fn build_tls_config(config: &Config) -> Result<axum_server::tls_rustls::RustlsConfig, HttpError> {
    let tls = &config.service.http.tls;
    let cert_path = tls
        .cert_path
        .as_ref()
        .ok_or_else(|| HttpError::Tls("service.http.tls.cert_path must be set".to_string()))?;
    let key_path = tls
        .key_path
        .as_ref()
        .ok_or_else(|| HttpError::Tls("service.http.tls.key_path must be set".to_string()))?;

    let mut certs = load_certs(cert_path).map_err(HttpError::Tls)?;
    if let Some(ca_path) = &tls.ca_path {
        let mut ca_certs = load_certs(ca_path).map_err(HttpError::Tls)?;
        certs.append(&mut ca_certs);
    }

    let key = load_private_key(key_path).map_err(HttpError::Tls)?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| HttpError::Tls(err.to_string()))?;

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(server_config),
    ))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut reader = io::BufReader::new(std::fs::File::open(path).map_err(|err| err.to_string())?);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    if certs.is_empty() {
        return Err("no certificates found".to_string());
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let mut reader = io::BufReader::new(std::fs::File::open(path).map_err(|err| err.to_string())?);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| "no private key found".to_string())?;
    Ok(key)
}

fn bad_request(message: &str) -> Response {
    let body = Json(ErrorResponse {
        error: message.to_string(),
    });
    (StatusCode::BAD_REQUEST, body).into_response()
}

fn payload_too_large(message: &str) -> Response {
    let body = Json(ErrorResponse {
        error: message.to_string(),
    });
    (StatusCode::PAYLOAD_TOO_LARGE, body).into_response()
}

fn server_error(message: &str) -> Response {
    error!("http handler error: {message}");
    let body = Json(ErrorResponse {
        error: "internal error".to_string(),
    });
    (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
}
