//! SQLite storage: projects, runs with their final results, triage
//! decisions and an audit log of approvals.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

use crate::plan::ApiError;

pub type Db = SqlitePool;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    jobs TEXT NOT NULL,
    finished INTEGER NOT NULL DEFAULT 0,
    result TEXT
);
CREATE INDEX IF NOT EXISTS runs_by_project ON runs(project_id, created_at);
CREATE TABLE IF NOT EXISTS triage (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);
"#;

/// Opens (and creates, if needed) the database, e.g. `sqlite:///var/lib/sectestgen/sectestgen.db`.
pub async fn connect(url: &str) -> Result<Db, String> {
    let options = SqliteConnectOptions::from_str(url)
        .map_err(|e| format!("DATABASE_URL: {e}"))?
        .create_if_missing(true)
        .foreign_keys(true);
    // An in-memory database exists per connection, so tests use exactly one.
    let max = if url.contains(":memory:") { 1 } else { 5 };
    let pool = SqlitePoolOptions::new()
        .max_connections(max)
        .connect_with(options)
        .await
        .map_err(|e| format!("Cannot open database: {e}"))?;
    sqlx::raw_sql(SCHEMA)
        .execute(&pool)
        .await
        .map_err(|e| format!("Cannot create tables: {e}"))?;
    Ok(pool)
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

pub fn db_error(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Database error".into())
}

/// Records who did what, against which target, and when.
pub async fn audit(db: &Db, action: &str, detail: &str) {
    let res = sqlx::query("INSERT INTO audit (at, action, detail) VALUES (?, ?, ?)")
        .bind(now())
        .bind(action)
        .bind(detail)
        .execute(db)
        .await;
    if let Err(e) = res {
        tracing::error!("audit log write failed: {e}");
    }
}
