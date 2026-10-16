//! Types shared between the app and the runner.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

mod scope;
pub use scope::Scope;

/// A normalized technology tag with the evidence it was detected from,
/// e.g. `fw:actix-web` found in `backend/Cargo.lock`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    pub id: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

/// One predefined tool action. The runner can only execute these.
#[derive(Debug, Clone, Deserialize)]
pub struct CatalogAction {
    pub id: String,
    pub title: String,
    pub tool: String,
    /// `source` or `url`.
    pub input: String,
    /// `passive` or `active`.
    pub mode: String,
    #[serde(default)]
    pub est_minutes: u32,
    /// Argument list, never run through a shell. Placeholders: `{{ src }}`,
    /// `{{ out }}`, `{{ url }}`, `{{ rps }}`, `{{ delay_ms }}`, `{{ cargo_lock }}`,
    /// `{{ tools_dir }}`, and JSON-quoted `{{ url_q }}` / `{{ origin_regex_q }}` for files.
    pub command: Vec<String>,
    /// How to read the results: `sarif` or `cargo-audit`.
    pub parser: Option<String>,
    /// File the parser reads; stdout when omitted.
    pub output: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_minutes: u64,
    /// Severity for every finding, for tools that don't report one.
    pub severity: Option<Severity>,
    /// Exit codes that mean the scan completed. Most tools exit with 1 when
    /// they find something; anything else is treated as a failed run.
    #[serde(default = "default_ok_exit_codes")]
    pub ok_exit_codes: Vec<i32>,
    /// Files written to the output directory before the tool starts (e.g. a
    /// ZAP automation plan), with the same placeholders as `command`.
    #[serde(default)]
    pub files: std::collections::BTreeMap<String, String>,
}

fn default_timeout() -> u64 {
    30
}

fn default_ok_exit_codes() -> Vec<i32> {
    vec![0, 1]
}

/// Loads every `*.yaml` action in `dir`, keyed by id.
pub fn load_catalog(dir: &Path) -> Result<HashMap<String, CatalogAction>, String> {
    let mut catalog = HashMap::new();
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for path in entries.filter_map(|e| e.ok().map(|e| e.path())) {
        if !path.extension().is_some_and(|x| x == "yaml" || x == "yml") {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let action: CatalogAction =
            serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        if catalog.contains_key(&action.id) {
            return Err(format!("duplicate catalog action {}", action.id));
        }
        catalog.insert(action.id.clone(), action);
    }
    Ok(catalog)
}

/// A tool result normalized into one shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub tool: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    /// `path/in/project.rs:14`, relative to the project root.
    pub location: Option<String>,
    pub message: String,
    pub snippet: Option<String>,
    /// How to fix it, when the tool says.
    pub help: Option<String>,
    pub help_url: Option<String>,
}

impl Finding {
    /// Identity used to merge duplicates across tools and runs.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}",
            self.tool,
            self.rule_id,
            self.location.as_deref().unwrap_or("")
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed,
    Stopped,
}

impl JobStatus {
    pub fn is_finished(self) -> bool {
        matches!(self, Self::Done | Self::Failed | Self::Stopped)
    }
}

/// Runner → app: result of unpacking an upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceInfo {
    pub workspace_id: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub tags: Vec<Tag>,
}

/// App → runner: start one catalog action on an uploaded workspace or a URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRequest {
    pub action_id: String,
    /// For `source` actions.
    pub workspace_id: Option<String>,
    /// For `url` actions; checked against the runner's own allowlist.
    pub url: Option<String>,
    pub rate_limit_rps: Option<u32>,
    /// Active actions only run when this equals the URL's hostname.
    pub confirm_host: Option<String>,
}

/// App → runner: passively fingerprint a URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintRequest {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobCreated {
    pub job_id: String,
}

/// Runner → app: current state of one job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobState {
    pub job_id: String,
    pub action_id: String,
    pub status: JobStatus,
    pub elapsed_secs: u64,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
    /// The last lines of combined stdout and stderr.
    pub log: Vec<String>,
    pub findings: Vec<Finding>,
}
