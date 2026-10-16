//! Project uploads and test runs, executed on the runner and stored in the
//! database, so results and history survive restarts.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::Json;
use common::{Finding, JobRequest, JobStatus};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::db::{self, db_error};
use crate::history::{self, Comparison, ProjectData, Triage};
use crate::plan::{bad_request, build_plan, parse_target_url, ApiError};
use crate::rules::DetectedTag;
use crate::runner::RunnerClient;
use crate::AppState;

/// Log lines kept per job once a run has finished.
const STORED_LOG_LINES: usize = 100;

pub fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn is_id(s: &str) -> bool {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunJob {
    pub job_id: String,
    pub action_id: String,
    pub title: String,
    pub tool: String,
    /// Titles of the plan tests this job covers.
    pub tests: Vec<String>,
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
    /// Existing project to add the run to; a new project is created otherwise.
    project_id: Option<String>,
    project: ProjectData,
    selected: Vec<String>,
    /// The hostname the user typed to confirm active tests.
    confirm_host: Option<String>,
}

#[derive(Serialize)]
pub struct RunCreated {
    run_id: String,
    project_id: String,
    jobs: Vec<RunJob>,
}

pub async fn create_run(
    State(state): State<AppState>,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunCreated>, ApiError> {
    let project = &req.project;
    if project.name.len() > 200 || project.description.len() > 10_000 || project.tags.len() > 500 {
        return Err(bad_request("Project details are too long"));
    }
    let workspace = match project.upload.as_ref().map(|u| u.workspace_id.as_str()) {
        Some(id) if is_id(id) => Some(id.to_string()),
        Some(_) => return Err(bad_request("Invalid upload id")),
        None => None,
    };
    let runner = runner(&state)?;
    let url = parse_target_url(&project.url)?;
    // URL tests are skipped (not refused) when the URL is out of scope, so code tests still run.
    let url_scope = match &url {
        Some(u) => state.scope.check_url(u).await.map(|_| ()),
        None => Err("No target URL was given".to_string()),
    };
    let tags: Vec<String> = project.tags.iter().map(|t| t.id.clone()).collect();
    let selected: HashSet<&str> = req.selected.iter().map(String::as_str).collect();
    let plan = build_plan(&state.knowledge, &tags, url.as_ref().map(url::Url::as_str));
    let host = url.as_ref().and_then(|u| u.host_str()).unwrap_or_default();

    // One job per catalog action, even when several selected tests use it.
    let mut jobs: Vec<RunJob> = Vec::new();
    let mut active = false;
    for item in plan
        .iter()
        .filter(|i| selected.contains(i.rule_id.as_str()))
    {
        if item.active && url_scope.is_ok() {
            if req.confirm_host.as_deref() != Some(host) {
                return Err(bad_request(format!(
                    "\"{}\" is an active test. Confirm it by typing the hostname.",
                    item.title
                )));
            }
            active = true;
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
        return Err(bad_request(match &url_scope {
            Err(e) if url.is_some() => format!("None of the selected tests can run: {e}."),
            _ => "None of the selected tests can run here. Upload the project or enter an allowed URL.".into(),
        }));
    }

    let project_id = history::upsert_project(&state.db, req.project_id.as_deref(), project).await?;
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
            rate_limit_rps: Some(project.rps),
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
    sqlx::query("INSERT INTO runs (id, project_id, created_at, jobs) VALUES (?, ?, ?, ?)")
        .bind(&run_id)
        .bind(&project_id)
        .bind(db::now())
        .bind(serde_json::to_string(&jobs).expect("serializable"))
        .execute(&state.db)
        .await
        .map_err(db_error)?;
    let actions: Vec<&str> = jobs.iter().map(|j| j.action_id.as_str()).collect();
    let detail = format!(
        "run {run_id} project {project_id} ({}) url={} upload={} actions={}{}",
        project.name,
        project.url,
        workspace.as_deref().unwrap_or("-"),
        actions.join(","),
        if active { " ACTIVE confirmed" } else { "" }
    );
    db::audit(&state.db, "run.approve", &detail).await;
    tracing::info!("{detail}");
    Ok(Json(RunCreated {
        run_id,
        project_id,
        jobs,
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// What a finished run stores.
#[derive(Serialize, Deserialize)]
pub struct RunResult {
    pub jobs: Vec<JobView>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingView {
    #[serde(flatten)]
    pub finding: Finding,
    pub fingerprint: String,
    /// Not present in the project's previous run.
    pub is_new: bool,
    pub triage: Option<Triage>,
}

#[derive(Serialize)]
pub struct RunView {
    run_id: String,
    project_id: String,
    project_name: String,
    created_at: i64,
    pub finished: bool,
    jobs: Vec<JobView>,
    pub findings: Vec<FindingView>,
    comparison: Option<Comparison>,
}

/// Current job states from the runner, merged and deduplicated findings.
async fn poll_jobs(state: &AppState, jobs: Vec<RunJob>) -> (Vec<JobView>, Vec<Finding>) {
    let mut views = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen = HashSet::new();
    for job in jobs {
        let result = match runner(state) {
            Ok(r) => r.job(&job.job_id).await,
            Err(e) => Err(e),
        };
        let view = match result {
            Ok(s) => {
                let count = s.findings.len();
                findings.extend(
                    s.findings
                        .into_iter()
                        .filter(|f| seen.insert(f.fingerprint())),
                );
                JobView {
                    job,
                    status: s.status,
                    elapsed_secs: s.elapsed_secs,
                    exit_code: s.exit_code,
                    error: s.error,
                    log: s.log,
                    finding_count: count,
                }
            }
            Err(e) => JobView {
                job,
                status: JobStatus::Failed,
                elapsed_secs: 0,
                exit_code: None,
                error: Some(e.1),
                log: Vec::new(),
                finding_count: 0,
            },
        };
        views.push(view);
    }
    findings.sort_by(|a, b| {
        (a.severity, &a.title, &a.location).cmp(&(b.severity, &b.title, &b.location))
    });
    (views, findings)
}

pub async fn load_run_view(state: &AppState, id: &str) -> Result<RunView, ApiError> {
    let row: Option<(String, i64, String, i64, Option<String>)> = sqlx::query_as(
        "SELECT project_id, created_at, jobs, finished, result FROM runs WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(db_error)?;
    let (project_id, created_at, jobs_json, finished, result) =
        row.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Run not found".into()))?;
    let corrupt = |e: serde_json::Error| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Stored run is unreadable: {e}"),
        )
    };

    let (jobs, findings, finished) = match (finished, result) {
        (1, Some(result)) => {
            let r: RunResult = serde_json::from_str(&result).map_err(corrupt)?;
            (r.jobs, r.findings, true)
        }
        _ => {
            let (mut jobs, findings) =
                poll_jobs(state, serde_json::from_str(&jobs_json).map_err(corrupt)?).await;
            let done = jobs.iter().all(|j| j.status.is_finished());
            if done {
                for j in &mut jobs {
                    let skip = j.log.len().saturating_sub(STORED_LOG_LINES);
                    j.log.drain(..skip);
                }
                let stored = RunResult { jobs, findings };
                sqlx::query("UPDATE runs SET finished = 1, result = ? WHERE id = ?")
                    .bind(serde_json::to_string(&stored).expect("serializable"))
                    .bind(id)
                    .execute(&state.db)
                    .await
                    .map_err(db_error)?;
                db::audit(
                    &state.db,
                    "run.finish",
                    &format!("run {id}: {} findings", stored.findings.len()),
                )
                .await;
                (stored.jobs, stored.findings, true)
            } else {
                (jobs, findings, false)
            }
        }
    };

    let triage = history::triage_map(&state.db, &project_id).await?;
    let previous = history::previous_run(&state.db, &project_id, id).await?;
    let (new_keys, comparison) = match previous {
        Some((previous_run_id, previous_created_at, before)) => {
            let (new, fixed) = history::compare(&findings, &before);
            let new_count = findings
                .iter()
                .filter(|f| new.contains(&history::stable_key(f)))
                .count();
            let comparison = Comparison {
                previous_run_id,
                previous_created_at,
                new_count,
                unchanged_count: findings.len() - new_count,
                fixed,
            };
            (Some(new), Some(comparison))
        }
        None => (None, None),
    };
    let findings = findings
        .into_iter()
        .map(|f| {
            let fingerprint = f.fingerprint();
            FindingView {
                is_new: new_keys
                    .as_ref()
                    .is_some_and(|n| n.contains(&history::stable_key(&f))),
                triage: triage.get(&fingerprint).cloned(),
                fingerprint,
                finding: f,
            }
        })
        .collect();
    let project_name = history::project_data(&state.db, &project_id)
        .await
        .map(|p| p.name)
        .unwrap_or_default();
    Ok(RunView {
        run_id: id.to_string(),
        project_id,
        project_name,
        created_at,
        finished,
        jobs,
        findings,
        comparison,
    })
}

pub async fn get_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<RunView>, ApiError> {
    load_run_view(&state, &id).await.map(Json)
}

async fn run_jobs(state: &AppState, id: &str) -> Result<Vec<RunJob>, ApiError> {
    let (jobs,): (String,) = sqlx::query_as("SELECT jobs FROM runs WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(db_error)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Run not found".into()))?;
    serde_json::from_str(&jobs)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

pub async fn stop_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let jobs = run_jobs(&state, &id).await?;
    let runner = runner(&state)?;
    for job in jobs {
        let _ = runner.stop(&job.job_id).await;
    }
    db::audit(&state.db, "run.stop", &id).await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn stop_job(
    State(state): State<AppState>,
    Path((id, job_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    if !run_jobs(&state, &id)
        .await?
        .iter()
        .any(|j| j.job_id == job_id)
    {
        return Err(ApiError(StatusCode::NOT_FOUND, "Job not found".into()));
    }
    runner(&state)?.stop(&job_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
