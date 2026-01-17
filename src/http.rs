use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tokio_util::io::ReaderStream;

use crate::build::{execute_build, validate_request};
use crate::config::{Config, HttpAuthConfig};
use crate::protocol::Request;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("failed to bind http server: {0}")]
    Bind(#[from] io::Error),

    #[error("http server failed: {0}")]
    Serve(String),

    #[error("tls configuration error: {0}")]
    Tls(String),
}

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
}

#[derive(serde::Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn run(config: Arc<Config>) -> Result<(), HttpError> {
    let addr: SocketAddr = config
        .service
        .http
        .listen_addr
        .parse()
        .map_err(|err| HttpError::Bind(io::Error::new(io::ErrorKind::InvalidInput, err)))?;

    let tls_enabled = config.service.http.tls.enabled;
    let tls_config = if tls_enabled {
        Some(build_tls_config(config.as_ref())?)
    } else {
        None
    };
    let state = AppState { config };
    let app = Router::new()
        .route("/v1/builds", post(start_build))
        .route("/v1/builds/:build_id/artifacts/*path", get(get_artifact))
        .with_state(state);

    if let Some(tls_config) = tls_config {
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

async fn start_build(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<Request>,
) -> Response {
    if let Some(response) = authorize(&headers, &state.config.service.http.auth) {
        return response;
    }

    let validated = match validate_request(request, &state.config) {
        Ok(validated) => validated,
        Err(err) => {
            let body = Json(ErrorResponse { error: err.message });
            return (StatusCode::BAD_REQUEST, body).into_response();
        }
    };

    let (tx, rx) = mpsc::channel(128);
    let config = Arc::clone(&state.config);
    tokio::task::spawn_blocking(move || execute_build(validated, config, tx));

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
    AxumPath((build_id, path)): AxumPath<(String, String)>,
) -> Response {
    if let Some(response) = authorize(&headers, &state.config.service.http.auth) {
        return response;
    }

    let root = state.config.artifacts.storage_root.join(&build_id);
    let candidate = root.join(&path);

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

    let content_type = content_type_for_path(&resolved);
    let stream = ReaderStream::new(file);

    let mut response = Response::new(Body::from_stream(stream));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response
}

fn authorize(headers: &HeaderMap, auth: &HttpAuthConfig) -> Option<Response> {
    if !auth.required {
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

fn content_type_for_path(path: &Path) -> HeaderValue {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    HeaderValue::from_str(mime.as_ref())
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))
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
