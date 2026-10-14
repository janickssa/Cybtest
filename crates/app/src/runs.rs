//! Project uploads and test runs, executed on the runner.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use common::{Finding, JobRequest, JobState, JobStatus};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::plan::{bad_request, build_plan, parse_target_url, ApiError};
use crate::rules::DetectedTag;
use crate::runner::RunnerClient;
use crate::AppState;

const MAX_RUNS: usize = 50;

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn is_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn runner(state: &AppState) -> Result<&Arc<RunnerClient>, ApiError> {
    state.runner.as_ref().ok_or_else(|| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "No runner is configured (set RUNNER_URL and RUNNER_TOKEN).".into(),
        )
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct RunJob {
    pub job_id: String,
    pub action_id: String,
    pub title: String,
    pub tool: String,
    /// Titles of the plan tests this job covers.
    pub tests: Vec<String>,
}

struct Run {
    seq: u64,
    jobs: Vec<RunJob>,
}

#[derive(Default)]
pub struct Runs {
    runs: Mutex<HashMap<String, Run>>,
    seq: Mutex<u64>,
}

impl Runs {
    fn insert(&self, id: String, jobs: Vec<RunJob>) {
        let seq = {
            let mut s = self.seq.lock().unwrap();
            *s += 1;
            *s
        };
        let mut runs = self.runs.lock().unwrap();
        if runs.len() >= MAX_RUNS {
            if let Some(oldest) = runs
                .iter()
                .min_by_key(|(_, r)| r.seq)
                .map(|(k, _)| k.clone())
            {
                runs.remove(&oldest);
            }
        }
        runs.insert(id, Run { seq, jobs });
    }

    fn jobs(&self, id: &str) -> Option<Vec<RunJob>> {
        self.runs.lock().unwrap().get(id).map(|r| r.jobs.clone())
    }
}

#[derive(Serialize)]
pub struct UploadResponse {
    workspace_id: String,
    file_count: usize,
    total_bytes: u64,
    tags: Vec<DetectedTag>,
}

pub async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<UploadResponse>, ApiError> {
    // A non-form content type means browsers won't send this cross-site without CORS approval.
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !matches!(
        content_type,
        "application/zip" | "application/x-zip-compressed" | "application/octet-stream"
    ) {
        return Err(bad_request("Upload a .zip file"));
    }
    if !(body.starts_with(b"PK\x03\x04") || body.starts_with(b"PK\x05\x06")) {
        return Err(bad_request("That file is not a zip archive"));
    }
    let info = runner(&state)?.upload(body).await?;
    let found: BTreeMap<String, String> =
        info.tags.into_iter().map(|t| (t.id, t.evidence)).collect();
    Ok(Json(UploadResponse {
        workspace_id: info.workspace_id,
        file_count: info.file_count,
        total_bytes: info.total_bytes,
        tags: state.knowledge.with_implied(found),
    }))
}

#[derive(Deserialize)]
pub struct RunRequest {
    #[serde(default)]
    workspace_id: Option<String>,
    #[serde(default)]
    url: String,
    tags: Vec<String>,
    selected: Vec<String>,
    rate_limit_rps: Option<u32>,
    /// The hostname the user typed to confirm active tests.
    confirm_host: Option<String>,
}

#[derive(Serialize)]
pub struct RunCreated {
    run_id: String,
    jobs: Vec<RunJob>,
}

pub async fn create_run(
    State(state): State<AppState>,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunCreated>, ApiError> {
    let workspace = match req.workspace_id.as_deref().filter(|w| !w.is_empty()) {
        Some(id) if is_id(id) => Some(id.to_string()),
        Some(_) => return Err(bad_request("Invalid upload id")),
        None => None,
    };
    let runner = runner(&state)?;
    let url = parse_target_url(&req.url)?;
    // URL tests are skipped (not refused) when the URL is out of scope, so code tests still run.
    let url_scope = match &url {
        Some(u) => state.scope.check_url(u).await.map(|_| ()),
        None => Err("No target URL was given".to_string()),
    };
    let selected: HashSet<&str> = req.selected.iter().map(String::as_str).collect();
    let plan = build_plan(
        &state.knowledge,
        &req.tags,
        url.as_ref().map(url::Url::as_str),
    );
    let host = url.as_ref().and_then(|u| u.host_str()).unwrap_or_default();

    // One job per catalog action, even when several selected tests use it.
    let mut jobs: Vec<RunJob> = Vec::new();
    for item in plan
        .iter()
        .filter(|i| selected.contains(i.rule_id.as_str()))
    {
        if item.active && url_scope.is_ok() && req.confirm_host.as_deref() != Some(host) {
            return Err(bad_request(format!(
                "\"{}\" is an active test. Confirm it by typing the hostname.",
                item.title
            )));
        }
        let runnable = item.actions.iter().filter(|a| match a.input.as_str() {
            "source" => workspace.is_some() && a.mode == "passive",
            "url" => url_scope.is_ok(),
            _ => false,
        });
        for action in runnable {
            match jobs.iter_mut().find(|j| j.action_id == action.id) {
                Some(job) => job.tests.push(item.title.clone()),
                None => jobs.push(RunJob {
                    job_id: String::new(),
                    action_id: action.id.clone(),
                    title: action.title.clone(),
                    tool: action.tool.clone(),
                    tests: vec![item.title.clone()],
                }),
            }
        }
    }
    if jobs.is_empty() {
        return Err(bad_request(
            match &url_scope {
            Err(e) if url.is_some() => format!("None of the selected tests can run: {e}."),
            _ => "None of the selected tests can run here. Upload the project or enter an allowed URL.".into(),
        }));
    }
    let needs_url = |action_id: &str| {
        state
            .knowledge
            .catalog
            .get(action_id)
            .is_some_and(|a| a.input == "url")
    };
    for i in 0..jobs.len() {
        let is_url = needs_url(&jobs[i].action_id);
        let request = JobRequest {
            action_id: jobs[i].action_id.clone(),
            workspace_id: if is_url { None } else { workspace.clone() },
            url: if is_url {
                url.as_ref().map(|u| u.to_string())
            } else {
                None
            },
            rate_limit_rps: req.rate_limit_rps,
            confirm_host: req.confirm_host.clone(),
        };
        match runner.start_job(&request).await {
            Ok(created) => jobs[i].job_id = created.job_id,
            Err(e) => {
                for started in &jobs[..i] {
                    let _ = runner.stop(&started.job_id).await;
                }
                return Err(e);
            }
        }
    }
    let run_id = random_id();
    tracing::info!(run = %run_id, jobs = jobs.len(), url = %req.url, workspace = ?workspace, "run approved");
    state.runs.insert(run_id.clone(), jobs.clone());
    Ok(Json(RunCreated { run_id, jobs }))
}

#[derive(Serialize)]
pub struct JobView {
    #[serde(flatten)]
    job: RunJob,
    status: JobStatus,
    elapsed_secs: u64,
    exit_code: Option<i32>,
    error: Option<String>,
    log: Vec<String>,
    finding_count: usize,
}

#[derive(Serialize)]
pub struct RunView {
    run_id: String,
    finished: bool,
    jobs: Vec<JobView>,
    findings: Vec<Finding>,
}

fn run_jobs(state: &AppState, id: &str) -> Result<Vec<RunJob>, ApiError> {
    state
        .runs
        .jobs(id)
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Run not found".into()))
}

pub async fn get_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<RunView>, ApiError> {
    let jobs = run_jobs(&state, &id)?;
    let runner = runner(&state)?;
    let mut views = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen = HashSet::new();
    for job in jobs {
        let s = runner.job(&job.job_id).await.unwrap_or_else(|e| JobState {
            job_id: job.job_id.clone(),
            action_id: job.action_id.clone(),
            status: JobStatus::Failed,
            elapsed_secs: 0,
            exit_code: None,
            error: Some(e.1),
            log: Vec::new(),
            findings: Vec::new(),
        });
        let count = s.findings.len();
        findings.extend(
            s.findings
                .into_iter()
                .filter(|f| seen.insert(f.fingerprint())),
        );
        views.push(JobView {
            job,
            status: s.status,
            elapsed_secs: s.elapsed_secs,
            exit_code: s.exit_code,
            error: s.error,
            log: s.log,
            finding_count: count,
        });
    }
    findings.sort_by(|a, b| {
        (a.severity, &a.title, &a.location).cmp(&(b.severity, &b.title, &b.location))
    });
    Ok(Json(RunView {
        run_id: id,
        finished: views.iter().all(|v| v.status.is_finished()),
        jobs: views,
        findings,
    }))
}

pub async fn stop_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let runner = runner(&state)?;
    for job in run_jobs(&state, &id)? {
        let _ = runner.stop(&job.job_id).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn stop_job(
    State(state): State<AppState>,
    Path((id, job_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    if !run_jobs(&state, &id)?.iter().any(|j| j.job_id == job_id) {
        return Err(ApiError(StatusCode::NOT_FOUND, "Job not found".into()));
    }
    runner(&state)?.stop(&job_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
