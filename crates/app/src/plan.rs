//! Turns tags into a ranked test plan, and the API endpoints around it.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::export;
use crate::rules::{DetectedTag, Knowledge, Severity, TagDef};

const MAX_DESCRIPTION: usize = 10_000;

#[derive(Debug, Clone, Serialize)]
pub struct PlanAction {
    pub id: String,
    pub title: String,
    pub tool: String,
    pub input: String,
    pub mode: String,
    pub est_minutes: u32,
    pub command: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanItem {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub references: Vec<String>,
    pub description: String,
    pub expected_secure_behavior: Option<String>,
    /// Labels of the tags that triggered this rule.
    pub why: Vec<String>,
    pub actions: Vec<PlanAction>,
    pub active: bool,
    pub preselected: bool,
}

/// Quotes an argument for display if it contains anything a shell would split on.
fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_alphanumeric() || "-_./:=@{}%,+".contains(c))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

fn render_command(args: &[String], url: Option<&str>) -> String {
    args.iter()
        .map(|a| match url {
            Some(url) => a.replace("{{ url }}", url),
            None => a.clone(),
        })
        .map(|a| shell_quote(&a))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn build_plan(k: &Knowledge, tags: &[String], url: Option<&str>) -> Vec<PlanItem> {
    let tag_set: HashSet<&str> = tags.iter().map(String::as_str).collect();
    let mut items: Vec<PlanItem> = k
        .rules
        .iter()
        .filter_map(|rule| {
            let matched = rule.when.matches(&tag_set)?;
            let actions: Vec<PlanAction> = rule
                .actions
                .iter()
                .map(|a| {
                    let c = &k.catalog[&a.id];
                    PlanAction {
                        id: c.id.clone(),
                        title: c.title.clone(),
                        tool: c.tool.clone(),
                        input: c.input.clone(),
                        mode: c.mode.clone(),
                        est_minutes: c.est_minutes,
                        command: render_command(&c.command, url),
                    }
                })
                .collect();
            let active = actions.iter().any(|a| a.mode == "active");
            Some(PlanItem {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity,
                references: rule.references.clone(),
                description: rule.description.trim().to_string(),
                expected_secure_behavior: rule.expected_secure_behavior.clone(),
                why: if matched.is_empty() {
                    vec!["Always recommended".into()]
                } else {
                    matched.iter().map(|t| k.tag_label(t)).collect()
                },
                actions,
                active,
                preselected: !active,
            })
        })
        .collect();
    items.sort_by(|a, b| (a.active, a.severity, &a.title).cmp(&(b.active, b.severity, &b.title)));
    items
}

#[derive(Debug)]
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad_request(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

/// Accepts only absolute http(s) URLs. An empty string means "no URL".
pub fn parse_target_url(raw: &str) -> Result<Option<url::Url>, ApiError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let url = url::Url::parse(raw).map_err(|e| bad_request(format!("Invalid URL: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
        return Err(bad_request("URL must start with http:// or https://"));
    }
    Ok(Some(url))
}

pub async fn tags(State(k): State<Arc<Knowledge>>) -> Json<Vec<TagDef>> {
    Json(k.tags.clone())
}

#[derive(Deserialize)]
pub struct AnalyzeRequest {
    #[serde(default)]
    description: String,
    #[serde(default)]
    url: String,
}

pub async fn analyze(
    State(k): State<Arc<Knowledge>>,
    Json(req): Json<AnalyzeRequest>,
) -> Result<Json<Vec<DetectedTag>>, ApiError> {
    if req.description.len() > MAX_DESCRIPTION {
        return Err(bad_request("Description is too long"));
    }
    let url = parse_target_url(&req.url)?;
    Ok(Json(k.detect(&req.description, url.as_ref())))
}

#[derive(Deserialize)]
pub struct PlanRequest {
    tags: Vec<String>,
    #[serde(default)]
    url: String,
}

pub async fn plan(
    State(k): State<Arc<Knowledge>>,
    Json(req): Json<PlanRequest>,
) -> Result<Json<Vec<PlanItem>>, ApiError> {
    let url = parse_target_url(&req.url)?;
    Ok(Json(build_plan(
        &k,
        &req.tags,
        url.as_ref().map(url::Url::as_str),
    )))
}

#[derive(Deserialize)]
pub struct ExportRequest {
    #[serde(default)]
    project_name: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    description: String,
    tags: Vec<String>,
    /// Rule ids the user kept selected.
    selected: Vec<String>,
}

pub async fn export_markdown(
    State(k): State<Arc<Knowledge>>,
    Json(req): Json<ExportRequest>,
) -> Result<Response, ApiError> {
    if req.description.len() > MAX_DESCRIPTION {
        return Err(bad_request("Description is too long"));
    }
    let url = parse_target_url(&req.url)?;
    let url = url.as_ref().map(url::Url::as_str);
    let selected: HashSet<&str> = req.selected.iter().map(String::as_str).collect();
    let items: Vec<PlanItem> = build_plan(&k, &req.tags, url)
        .into_iter()
        .filter(|i| selected.contains(i.rule_id.as_str()))
        .collect();
    let tag_labels: Vec<String> = req.tags.iter().map(|t| k.tag_label(t)).collect();
    let name = req.project_name.trim();
    let name = if name.is_empty() {
        "Untitled project"
    } else {
        name
    };
    let body = export::markdown(name, url, req.description.trim(), &tag_labels, &items);
    let filename: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    Ok((
        [
            (
                header::CONTENT_TYPE,
                "text/markdown; charset=utf-8".to_string(),
            ),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}-test-plan.md\""),
            ),
        ],
        body,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn knowledge() -> Knowledge {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        Knowledge::load(&root.join("rules"), &root.join("catalog")).unwrap()
    }

    #[test]
    fn active_tests_are_never_preselected_and_sorted_last() {
        let k = knowledge();
        let tags = vec!["input:url".to_string(), "proto:https".to_string()];
        let plan = build_plan(&k, &tags, Some("https://test.example.dk/"));
        let active = plan
            .iter()
            .find(|i| i.rule_id == "full-active-scan")
            .unwrap();
        assert!(active.active && !active.preselected);
        assert!(plan.last().unwrap().active);
        let tls = plan
            .iter()
            .find(|i| i.rule_id == "tls-configuration")
            .unwrap();
        assert!(tls.preselected);
        assert!(tls.actions[0].command.contains("https://test.example.dk/"));
    }

    #[test]
    fn sqlx_without_orm_triggers_raw_sql_rule() {
        let k = knowledge();
        let ids = |tags: &[&str]| -> Vec<String> {
            let tags: Vec<String> = tags.iter().map(|t| t.to_string()).collect();
            build_plan(&k, &tags, None)
                .into_iter()
                .map(|i| i.rule_id)
                .collect()
        };
        assert!(ids(&["lib:sqlx"]).contains(&"rust-raw-sql".to_string()));
        assert!(!ids(&["lib:sqlx", "db:orm"]).contains(&"rust-raw-sql".to_string()));
    }

    #[test]
    fn rejects_non_http_urls() {
        assert!(parse_target_url("file:///etc/passwd").is_err());
        assert!(parse_target_url("javascript:alert(1)").is_err());
        assert!(parse_target_url("").unwrap().is_none());
        assert!(parse_target_url("https://internaltest.example.dk")
            .unwrap()
            .is_some());
    }

    #[test]
    fn quotes_arguments_for_display() {
        assert_eq!(shell_quote("p/default"), "p/default");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }
}
