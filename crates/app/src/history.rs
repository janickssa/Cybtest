//! Saved projects, their run history, triage decisions (false positive /
//! accepted risk), comparison between runs, and SARIF export.

use std::collections::{HashMap, HashSet};

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use common::{Finding, Severity};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::db::{self, db_error, Db};
use crate::plan::{bad_request, ApiError};
use crate::rules::DetectedTag;
use crate::runs::{is_id, load_run_view, random_id, FindingView, RunResult};
use crate::AppState;

fn default_rps() -> u32 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadInfo {
    pub workspace_id: String,
    pub name: String,
    pub file_count: usize,
    pub total_bytes: u64,
}

/// Everything the wizard needs to reopen a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectData {
    pub name: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_rps")]
    pub rps: u32,
    pub tags: Vec<DetectedTag>,
    pub upload: Option<UploadInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counts {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl Counts {
    pub fn of<'a>(findings: impl IntoIterator<Item = &'a Finding>) -> Self {
        let mut c = Self::default();
        for f in findings {
            match f.severity {
                Severity::High => c.high += 1,
                Severity::Medium => c.medium += 1,
                Severity::Low => c.low += 1,
                Severity::Info => c.info += 1,
            }
        }
        c
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Triage {
    /// `false_positive` or `accepted_risk`.
    pub status: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Comparison {
    pub previous_run_id: String,
    pub previous_created_at: i64,
    pub new_count: usize,
    pub unchanged_count: usize,
    pub fixed: Vec<Finding>,
}

/// Identity for comparing runs: like the fingerprint, but without the line
/// number, so a finding that only moved isn't reported as new and fixed.
pub fn stable_key(f: &Finding) -> String {
    let location = f.location.as_deref().unwrap_or("");
    let location = match location.rsplit_once(':') {
        Some((path, line)) if !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()) => path,
        _ => location,
    };
    format!("{}|{}|{}", f.tool, f.rule_id, location)
}

/// Keys of findings that are new in `current`, plus findings that disappeared.
pub fn compare(current: &[Finding], previous: &[Finding]) -> (HashSet<String>, Vec<Finding>) {
    let before: HashSet<String> = previous.iter().map(stable_key).collect();
    let now: HashSet<String> = current.iter().map(stable_key).collect();
    let new = now.difference(&before).cloned().collect();
    let mut seen = HashSet::new();
    let fixed = previous
        .iter()
        .filter(|f| !now.contains(&stable_key(f)) && seen.insert(stable_key(f)))
        .cloned()
        .collect();
    (new, fixed)
}

pub async fn upsert_project(
    db: &Db,
    id: Option<&str>,
    data: &ProjectData,
) -> Result<String, ApiError> {
    let json = serde_json::to_string(data).expect("serializable");
    if let Some(id) = id.filter(|id| is_id(id)) {
        let updated = sqlx::query("UPDATE projects SET data = ?, updated_at = ? WHERE id = ?")
            .bind(&json)
            .bind(db::now())
            .bind(id)
            .execute(db)
            .await
            .map_err(db_error)?;
        if updated.rows_affected() == 1 {
            return Ok(id.to_string());
        }
    }
    let id = random_id();
    sqlx::query("INSERT INTO projects (id, data, created_at, updated_at) VALUES (?, ?, ?, ?)")
        .bind(&id)
        .bind(&json)
        .bind(db::now())
        .bind(db::now())
        .execute(db)
        .await
        .map_err(db_error)?;
    Ok(id)
}

pub async fn project_data(db: &Db, id: &str) -> Result<ProjectData, ApiError> {
    let (data,): (String,) = sqlx::query_as("SELECT data FROM projects WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(db_error)?
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Project not found".into()))?;
    serde_json::from_str(&data)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

pub async fn triage_map(db: &Db, project_id: &str) -> Result<HashMap<String, Triage>, ApiError> {
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT fingerprint, status, note FROM triage WHERE project_id = ?")
            .bind(project_id)
            .fetch_all(db)
            .await
            .map_err(db_error)?;
    Ok(rows
        .into_iter()
        .map(|(fp, status, note)| (fp, Triage { status, note }))
        .collect())
}

/// The project's latest finished run created before `run_id`, with its findings.
pub async fn previous_run(
    db: &Db,
    project_id: &str,
    run_id: &str,
) -> Result<Option<(String, i64, Vec<Finding>)>, ApiError> {
    let row: Option<(String, i64, String)> = sqlx::query_as(
        "SELECT id, created_at, result FROM runs WHERE project_id = ? AND finished = 1 AND result IS NOT NULL \
         AND rowid < (SELECT rowid FROM runs WHERE id = ?) ORDER BY rowid DESC LIMIT 1",
    )
    .bind(project_id)
    .bind(run_id)
    .fetch_optional(db)
    .await
    .map_err(db_error)?;
    Ok(row.and_then(|(id, at, result)| {
        let result: RunResult = serde_json::from_str(&result).ok()?;
        Some((id, at, result.findings))
    }))
}

#[derive(Serialize)]
pub struct RunSummary {
    id: String,
    created_at: i64,
    finished: bool,
    counts: Option<Counts>,
}

#[derive(Serialize)]
pub struct ProjectSummary {
    id: String,
    name: String,
    url: String,
    tags: Vec<String>,
    upload_name: Option<String>,
    updated_at: i64,
    last_run: Option<RunSummary>,
}

async fn run_summaries(db: &Db, project_id: &str, limit: i64) -> Result<Vec<RunSummary>, ApiError> {
    let rows: Vec<(String, i64, i64, Option<String>)> = sqlx::query_as(
        "SELECT id, created_at, finished, result FROM runs WHERE project_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
    )
    .bind(project_id)
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(db_error)?;
    Ok(rows
        .into_iter()
        .map(|(id, created_at, finished, result)| RunSummary {
            id,
            created_at,
            finished: finished == 1,
            counts: result
                .and_then(|r| serde_json::from_str::<RunResult>(&r).ok())
                .map(|r| Counts::of(&r.findings)),
        })
        .collect())
}

pub async fn list_projects(
    State(state): State<AppState>,
) -> Result<Json<Vec<ProjectSummary>>, ApiError> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT id, data, updated_at FROM projects ORDER BY updated_at DESC LIMIT 200",
    )
    .fetch_all(&state.db)
    .await
    .map_err(db_error)?;
    let mut out = Vec::new();
    for (id, data, updated_at) in rows {
        let Ok(data) = serde_json::from_str::<ProjectData>(&data) else {
            continue;
        };
        let last_run = run_summaries(&state.db, &id, 1).await?.into_iter().next();
        out.push(ProjectSummary {
            id,
            name: data.name,
            url: data.url,
            tags: data
                .tags
                .into_iter()
                .filter(|t| !t.id.starts_with("input:"))
                .map(|t| t.label)
                .collect(),
            upload_name: data.upload.map(|u| u.name),
            updated_at,
            last_run,
        });
    }
    Ok(Json(out))
}

#[derive(Serialize)]
pub struct ProjectDetail {
    id: String,
    project: ProjectData,
    runs: Vec<RunSummary>,
}

pub async fn get_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ProjectDetail>, ApiError> {
    let project = project_data(&state.db, &id).await?;
    let runs = run_summaries(&state.db, &id, 50).await?;
    Ok(Json(ProjectDetail { id, project, runs }))
}

pub async fn delete_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let res = sqlx::query("DELETE FROM projects WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(db_error)?;
    if res.rows_affected() == 0 {
        return Err(ApiError(StatusCode::NOT_FOUND, "Project not found".into()));
    }
    db::audit(&state.db, "project.delete", &id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct TriageRequest {
    fingerprint: String,
    /// `false_positive`, `accepted_risk`, or null to show the finding again.
    status: Option<String>,
    #[serde(default)]
    note: String,
}

pub async fn set_triage(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    Json(req): Json<TriageRequest>,
) -> Result<StatusCode, ApiError> {
    project_data(&state.db, &project_id).await?;
    if req.fingerprint.is_empty() || req.fingerprint.len() > 2000 || req.note.len() > 2000 {
        return Err(bad_request("Invalid triage request"));
    }
    match req.status.as_deref() {
        Some(status @ ("false_positive" | "accepted_risk")) => {
            sqlx::query(
                "INSERT INTO triage (project_id, fingerprint, status, note, created_at) VALUES (?, ?, ?, ?, ?) \
                 ON CONFLICT (project_id, fingerprint) DO UPDATE SET status = excluded.status, note = excluded.note",
            )
            .bind(&project_id)
            .bind(&req.fingerprint)
            .bind(status)
            .bind(req.note.trim())
            .bind(db::now())
            .execute(&state.db)
            .await
            .map_err(db_error)?;
            db::audit(
                &state.db,
                &format!("triage.{status}"),
                &format!("{project_id} {}", req.fingerprint),
            )
            .await;
        }
        None => {
            sqlx::query("DELETE FROM triage WHERE project_id = ? AND fingerprint = ?")
                .bind(&project_id)
                .bind(&req.fingerprint)
                .execute(&state.db)
                .await
                .map_err(db_error)?;
            db::audit(
                &state.db,
                "triage.clear",
                &format!("{project_id} {}", req.fingerprint),
            )
            .await;
        }
        Some(_) => {
            return Err(bad_request(
                "Status must be false_positive or accepted_risk",
            ))
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

fn sarif_level(s: Severity) -> (&'static str, &'static str) {
    match s {
        Severity::High => ("error", "8.0"),
        Severity::Medium => ("warning", "5.0"),
        Severity::Low => ("note", "2.0"),
        Severity::Info => ("none", "0.0"),
    }
}

/// `src/a.rs:14` → file location with a line; URLs (possibly followed by
/// " and 6 more") → the URL alone.
fn sarif_location(location: &str) -> Value {
    if location.contains("://") {
        let uri = location.split_whitespace().next().unwrap_or(location);
        return json!({ "physicalLocation": { "artifactLocation": { "uri": uri } } });
    }
    match location.rsplit_once(':') {
        Some((path, line)) if line.parse::<u64>().is_ok_and(|l| l > 0) => json!({
            "physicalLocation": { "artifactLocation": { "uri": path }, "region": { "startLine": line.parse::<u64>().unwrap() } }
        }),
        _ => json!({ "physicalLocation": { "artifactLocation": { "uri": location } } }),
    }
}

/// SARIF 2.1.0 with one rule per tool/rule pair. Triaged findings are kept,
/// marked as suppressed, so code-scanning tools hide them too.
pub fn sarif(findings: &[FindingView]) -> Value {
    let mut rules: Vec<Value> = Vec::new();
    let mut rule_ids = HashSet::new();
    let mut results = Vec::new();
    for view in findings {
        let f = &view.finding;
        let id = format!("{}/{}", f.tool, f.rule_id);
        let (level, score) = sarif_level(f.severity);
        if rule_ids.insert(id.clone()) {
            let mut rule = json!({
                "id": id,
                "shortDescription": { "text": f.title },
                "properties": { "security-severity": score, "tags": ["security", f.tool] },
            });
            if let Some(help) = &f.help {
                rule["help"] = json!({ "text": help });
            }
            if let Some(url) = &f.help_url {
                rule["helpUri"] = json!(url);
            }
            rules.push(rule);
        }
        let text = if f.message.is_empty() {
            f.title.clone()
        } else {
            format!("{}: {}", f.title, f.message)
        };
        let mut result = json!({
            "ruleId": id,
            "level": level,
            "message": { "text": text },
            "partialFingerprints": { "sectestgen/v1": view.fingerprint },
            "properties": { "tool": f.tool, "severity": f.severity },
        });
        if let Some(loc) = &f.location {
            result["locations"] = json!([sarif_location(loc)]);
        }
        if let Some(t) = &view.triage {
            let reason = if t.status == "false_positive" {
                "False positive"
            } else {
                "Accepted risk"
            };
            let justification = if t.note.is_empty() {
                reason.to_string()
            } else {
                format!("{reason}: {}", t.note)
            };
            result["suppressions"] = json!([{ "kind": "external", "status": "accepted", "justification": justification }]);
        }
        results.push(result);
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "SecTestGen",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/janickssa/Cybtest",
                "rules": rules,
            }},
            "results": results,
        }],
    })
}

pub async fn export_sarif(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let view = load_run_view(&state, &id).await?;
    if !view.finished {
        return Err(bad_request("The run hasn't finished yet"));
    }
    let body = serde_json::to_string_pretty(&sarif(&view.findings)).expect("serializable");
    Ok((
        [
            (header::CONTENT_TYPE, "application/sarif+json".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"sectestgen-{}.sarif\"",
                    &id[..8.min(id.len())]
                ),
            ),
        ],
        body,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(tool: &str, rule: &str, location: Option<&str>, severity: Severity) -> Finding {
        Finding {
            tool: tool.into(),
            rule_id: rule.into(),
            title: format!("{rule} title"),
            severity,
            location: location.map(str::to_string),
            message: "msg".into(),
            snippet: None,
            help: Some("fix it".into()),
            help_url: None,
        }
    }

    #[test]
    fn comparison_ignores_moved_lines() {
        let before = vec![
            finding("semgrep", "sqli", Some("src/db.rs:10"), Severity::High),
            finding("trivy", "DS-0002", Some("Dockerfile:1"), Severity::High),
        ];
        let now = vec![
            finding("semgrep", "sqli", Some("src/db.rs:14"), Severity::High),
            finding("gitleaks", "github-pat", Some("a.py:2"), Severity::High),
        ];
        let (new, fixed) = compare(&now, &before);
        assert_eq!(new, HashSet::from(["gitleaks|github-pat|a.py".to_string()]));
        assert_eq!(fixed.len(), 1);
        assert_eq!(fixed[0].rule_id, "DS-0002");
    }

    #[test]
    fn sarif_has_rules_locations_and_suppressions() {
        let views = vec![
            FindingView {
                fingerprint: "fp1".into(),
                is_new: false,
                triage: None,
                finding: finding("semgrep", "sqli", Some("src/db.rs:14"), Severity::High),
            },
            FindingView {
                fingerprint: "fp2".into(),
                is_new: true,
                triage: Some(Triage {
                    status: "false_positive".into(),
                    note: "test data".into(),
                }),
                finding: finding(
                    "zap",
                    "10038-1",
                    Some("https://t.example/ and 6 more"),
                    Severity::Medium,
                ),
            },
        ];
        let doc = sarif(&views);
        let run = &doc["runs"][0];
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 2);
        let r0 = &run["results"][0];
        assert_eq!(r0["level"], "error");
        assert_eq!(
            r0["locations"][0]["physicalLocation"]["region"]["startLine"],
            14
        );
        assert_eq!(
            r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/db.rs"
        );
        let r1 = &run["results"][1];
        assert_eq!(
            r1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://t.example/"
        );
        assert_eq!(
            r1["suppressions"][0]["justification"],
            "False positive: test data"
        );
        assert!(r0.get("suppressions").is_none());
    }
}
