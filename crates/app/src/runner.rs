//! HTTP client for the runner container.

use std::time::Duration;

use axum::body::Bytes;
use axum::http::StatusCode;
use common::{FingerprintRequest, JobCreated, JobRequest, JobState, Tag, WorkspaceInfo};
use serde::de::DeserializeOwned;

use crate::plan::ApiError;

/// The error with its causes, e.g. "error sending request: invalid peer certificate: …".
fn describe(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        msg = format!("{msg}: {cause}");
        source = cause.source();
    }
    msg
}

fn unreachable(e: reqwest::Error) -> ApiError {
    ApiError(
        StatusCode::BAD_GATEWAY,
        format!("Runner unreachable: {}", describe(&e)),
    )
}

pub struct RunnerClient {
    base: String,
    token: String,
    http: reqwest::Client,
}

impl RunnerClient {
    /// Reads `RUNNER_URL`, `RUNNER_TOKEN` and optional `RUNNER_CA_CERT` (PEM of
    /// the runner's self-signed certificate). `None` when no runner is configured.
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(base) = std::env::var("RUNNER_URL") else {
            return Ok(None);
        };
        let token = std::env::var("RUNNER_TOKEN")
            .map_err(|_| "RUNNER_URL is set but RUNNER_TOKEN is not")?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(600));
        if let Ok(path) = std::env::var("RUNNER_CA_CERT") {
            let pem = std::fs::read(&path).map_err(|e| format!("RUNNER_CA_CERT {path}: {e}"))?;
            let cert =
                reqwest::Certificate::from_pem(&pem).map_err(|e| format!("RUNNER_CA_CERT: {e}"))?;
            builder = builder.add_root_certificate(cert);
        }
        Ok(Some(Self {
            base: base.trim_end_matches('/').to_string(),
            token,
            http: builder.build().map_err(|e| e.to_string())?,
        }))
    }

    async fn send<T: DeserializeOwned>(&self, req: reqwest::RequestBuilder) -> Result<T, ApiError> {
        let res = req
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(unreachable)?;
        let status = res.status();
        if status.is_success() {
            return res.json().await.map_err(|e| {
                ApiError(StatusCode::BAD_GATEWAY, format!("Bad runner response: {e}"))
            });
        }
        let message = res
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_string))
            .unwrap_or_else(|| format!("Runner returned {status}"));
        let status = match status.as_u16() {
            400 | 404 | 413 => StatusCode::from_u16(status.as_u16()).unwrap(),
            _ => StatusCode::BAD_GATEWAY,
        };
        Err(ApiError(status, message))
    }

    pub async fn upload(&self, zip: Bytes) -> Result<WorkspaceInfo, ApiError> {
        self.send(
            self.http
                .post(format!("{}/workspaces", self.base))
                .header("content-type", "application/zip")
                .body(zip),
        )
        .await
    }

    pub async fn fingerprint(&self, url: &str) -> Result<Vec<Tag>, ApiError> {
        let req = FingerprintRequest {
            url: url.to_string(),
        };
        self.send(
            self.http
                .post(format!("{}/fingerprint", self.base))
                .json(&req),
        )
        .await
    }

    pub async fn start_job(&self, req: &JobRequest) -> Result<JobCreated, ApiError> {
        self.send(self.http.post(format!("{}/jobs", self.base)).json(req))
            .await
    }

    pub async fn job(&self, id: &str) -> Result<JobState, ApiError> {
        self.send(self.http.get(format!("{}/jobs/{id}?lines=200", self.base)))
            .await
    }

    pub async fn stop(&self, id: &str) -> Result<(), ApiError> {
        let res = self
            .http
            .post(format!("{}/jobs/{id}/stop", self.base))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(unreachable)?;
        if res.status().is_success() {
            Ok(())
        } else {
            Err(ApiError(
                StatusCode::BAD_GATEWAY,
                format!("Runner returned {}", res.status()),
            ))
        }
    }
}
