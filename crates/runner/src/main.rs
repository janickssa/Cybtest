//! SecTestGen runner: unpacks uploads, detects the stack and runs approved
//! catalog actions. Only the app may talk to it, with a shared token.

mod detect;
mod execute;
mod mobile;
mod parsers;
mod recon;
mod unpack;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as UrlPath, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::{
    CatalogAction, FingerprintRequest, JobCreated, JobRequest, JobState, Scope, Tag, WorkspaceInfo,
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::json;

use execute::{ExecConfig, JobSpec, Jobs};

pub fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn is_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[derive(Clone)]
struct AppState {
    token: Arc<String>,
    workspaces: Arc<PathBuf>,
    catalog: Arc<HashMap<String, CatalogAction>>,
    jobs: Arc<Jobs>,
    limits: Arc<unpack::Limits>,
    scope: Arc<Scope>,
    rate: RateLimits,
}

#[derive(Clone, Copy)]
struct RateLimits {
    default_rps: u32,
    max_rps: u32,
}

/// Parses an http(s) URL and checks it against the runner's own allowlist,
/// resolving the hostname now (just before the job or request).
async fn checked_url(scope: &Scope, raw: &str) -> Result<url::Url, Error> {
    let url = url::Url::parse(raw).map_err(|e| bad_request(format!("Invalid URL: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(bad_request("Only http and https URLs can be scanned"));
    }
    scope
        .check_url(&url)
        .await
        .map_err(|e| Error(StatusCode::FORBIDDEN, e))?;
    Ok(url)
}

async fn fingerprint(
    State(state): State<AppState>,
    Json(req): Json<FingerprintRequest>,
) -> Result<Json<Vec<Tag>>, Error> {
    let url = checked_url(&state.scope, &req.url).await?;
    tracing::info!(url = %url, "fingerprint");
    recon::fingerprint(&state.scope, &url)
        .await
        .map(Json)
        .map_err(|e| Error(StatusCode::BAD_GATEWAY, e))
}

struct Error(StatusCode, String);

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad_request(msg: impl Into<String>) -> Error {
    Error(StatusCode::BAD_REQUEST, msg.into())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn require_token(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| constant_time_eq(t.as_bytes(), state.token.as_bytes()));
    if ok {
        next.run(req).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn create_workspace(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<WorkspaceInfo>, Error> {
    let id = random_id();
    let ws = state.workspaces.join(&id);
    let src = ws.join("src");
    tokio::fs::create_dir_all(&src)
        .await
        .map_err(|e| Error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let archive = ws.join("upload.zip");
    let result = async {
        tokio::fs::write(&archive, &body)
            .await
            .map_err(|e| e.to_string())?;
        let (archive, src, limits) = (archive.clone(), src.clone(), state.limits.clone());
        tokio::task::spawn_blocking(move || {
            let unpacked = unpack::unpack(&archive, &src, &limits)?;
            let _ = std::fs::remove_file(&archive);
            Ok::<_, String>((unpacked, detect::detect(&src)))
        })
        .await
        .map_err(|e| e.to_string())?
    }
    .await;
    match result {
        Ok((unpacked, tags)) => {
            tracing::info!(workspace = %id, files = unpacked.file_count, "unpacked upload");
            Ok(Json(WorkspaceInfo {
                workspace_id: id,
                file_count: unpacked.file_count,
                total_bytes: unpacked.total_bytes,
                tags,
            }))
        }
        Err(e) => {
            let _ = tokio::fs::remove_dir_all(&ws).await;
            Err(bad_request(e))
        }
    }
}

async fn create_job(
    State(state): State<AppState>,
    Json(req): Json<JobRequest>,
) -> Result<Json<JobCreated>, Error> {
    let action = state
        .catalog
        .get(&req.action_id)
        .ok_or_else(|| bad_request(format!("Unknown action {}", req.action_id)))?;
    let (ws, url) = match action.input.as_str() {
        "source" => {
            let id = req
                .workspace_id
                .as_deref()
                .filter(|id| is_id(id))
                .ok_or_else(|| bad_request("Invalid workspace id"))?;
            let ws = state.workspaces.join(id);
            if !ws.join("src").is_dir() {
                return Err(Error(
                    StatusCode::NOT_FOUND,
                    "Workspace not found (it may have expired)".into(),
                ));
            }
            (ws, None)
        }
        "url" => {
            let url = checked_url(
                &state.scope,
                req.url
                    .as_deref()
                    .ok_or_else(|| bad_request("This action needs a URL"))?,
            )
            .await?;
            if action.mode == "active" && req.confirm_host.as_deref() != url.host_str() {
                return Err(bad_request(format!(
                    "{} is an active test; confirm the hostname to run it",
                    action.title
                )));
            }
            let ws = state.workspaces.join(random_id());
            tokio::fs::create_dir_all(&ws)
                .await
                .map_err(|e| Error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            (ws, Some(url))
        }
        other => return Err(bad_request(format!("Unsupported input {other}"))),
    };
    let rps = req
        .rate_limit_rps
        .unwrap_or(state.rate.default_rps)
        .clamp(1, state.rate.max_rps);
    let target = url.as_ref().map_or_else(
        || req.workspace_id.clone().unwrap_or_default(),
        |u| u.to_string(),
    );
    let job_id = state.jobs.start(JobSpec {
        action: action.clone(),
        ws,
        url,
        rate_limit_rps: rps,
    });
    tracing::info!(job = %job_id, action = %req.action_id, %target, rps, mode = %action.mode, "job queued");
    Ok(Json(JobCreated { job_id }))
}

#[derive(Deserialize)]
struct LogQuery {
    lines: Option<usize>,
}

async fn job_state(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<String>,
    Query(q): Query<LogQuery>,
) -> Result<Json<JobState>, Error> {
    let job = state
        .jobs
        .get(&id)
        .ok_or(Error(StatusCode::NOT_FOUND, "Job not found".into()))?;
    Ok(Json(job.state(q.lines.unwrap_or(200).min(2000))))
}

async fn stop_job(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<String>,
) -> Result<StatusCode, Error> {
    let job = state
        .jobs
        .get(&id)
        .ok_or(Error(StatusCode::NOT_FOUND, "Job not found".into()))?;
    job.request_stop();
    Ok(StatusCode::NO_CONTENT)
}

fn router(state: AppState, max_upload: usize) -> Router {
    let protected = Router::new()
        .route(
            "/workspaces",
            post(create_workspace).layer(DefaultBodyLimit::max(max_upload)),
        )
        .route("/jobs", post(create_job))
        .route("/fingerprint", post(fingerprint))
        .route("/jobs/{id}", get(job_state))
        .route("/jobs/{id}/stop", post(stop_job))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token));
    Router::new()
        .route("/health", get(|| async { Json(json!({ "status": "ok" })) }))
        .merge(protected)
        .with_state(state)
}

/// Deletes workspaces older than `days`, every hour.
async fn cleanup_loop(dir: PathBuf, days: u64) {
    let max_age = Duration::from_secs(days * 24 * 60 * 60);
    loop {
        if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let old = entry
                    .metadata()
                    .await
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| t.elapsed().unwrap_or_default() > max_age);
                if old && is_id(&entry.file_name().to_string_lossy()) {
                    tracing::info!(workspace = %entry.file_name().to_string_lossy(), "deleting expired workspace");
                    let _ = tokio::fs::remove_dir_all(entry.path()).await;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn env_num(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let token = std::env::var("RUNNER_TOKEN").unwrap_or_default();
    if token.len() < 32 {
        fail("RUNNER_TOKEN must be set to a random secret of at least 32 characters");
    }
    let bind: SocketAddr = env_or("BIND_ADDR", "127.0.0.1:9090")
        .parse()
        .unwrap_or_else(|_| fail("BIND_ADDR must be host:port"));
    let workspaces = PathBuf::from(env_or("WORKSPACE_DIR", "workspaces"));
    std::fs::create_dir_all(&workspaces)
        .unwrap_or_else(|e| fail(format!("{}: {e}", workspaces.display())));
    let catalog = common::load_catalog(Path::new(&env_or("CATALOG_DIR", "catalog")))
        .unwrap_or_else(|e| fail(e));
    let max_upload = env_num("MAX_UPLOAD_MB", 200) as usize * 1024 * 1024;
    let limits = unpack::Limits {
        max_files: env_num("MAX_FILES", 50_000) as usize,
        max_bytes: env_num("MAX_UNPACKED_MB", 2048) * 1024 * 1024,
    };
    let jobs = Jobs::new(
        env_num("MAX_PARALLEL_JOBS", 2) as usize,
        ExecConfig {
            tools_path: env_or(
                "TOOLS_PATH",
                "/opt/sectestgen-runner/tools/bin:/usr/local/bin:/usr/bin:/bin",
            ),
            cache_dir: std::env::var("CACHE_DIR").ok().map(PathBuf::from),
            tools_dir: env_or("TOOLS_DIR", "/opt/sectestgen-runner/tools"),
        },
    );
    tokio::spawn(cleanup_loop(
        workspaces.clone(),
        env_num("WORKSPACE_RETENTION_DAYS", 7),
    ));
    tracing::info!("loaded {} catalog actions", catalog.len());

    let scope = Scope::parse(&env_or("SCOPE_ALLOWLIST", "")).unwrap_or_else(|e| fail(e));
    if scope.is_empty() {
        tracing::warn!("SCOPE_ALLOWLIST is empty: URL tests are refused");
    }
    let state = AppState {
        token: Arc::new(token),
        workspaces: Arc::new(workspaces),
        catalog: Arc::new(catalog),
        jobs: Arc::new(jobs),
        limits: Arc::new(limits),
        scope: Arc::new(scope),
        rate: RateLimits {
            default_rps: env_num("DEFAULT_RATE_LIMIT_RPS", 10) as u32,
            max_rps: env_num("MAX_RATE_LIMIT_RPS", 50) as u32,
        },
    };
    let app = router(state, max_upload);
    match (std::env::var("TLS_CERT"), std::env::var("TLS_KEY")) {
        (Ok(cert), Ok(key)) => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .unwrap_or_else(|e| fail(format!("TLS: {e}")));
            tracing::info!("listening on https://{bind}");
            axum_server::bind_rustls(bind, tls)
                .serve(app.into_make_service())
                .await
                .unwrap_or_else(|e| fail(e));
        }
        _ => {
            tracing::warn!("TLS_CERT/TLS_KEY not set: serving plain HTTP (development only)");
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .unwrap_or_else(|e| fail(e));
            tracing::info!("listening on http://{bind}");
            axum::serve(listener, app).await.unwrap_or_else(|e| fail(e));
        }
    }
}
