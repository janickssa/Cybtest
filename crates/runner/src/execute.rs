//! Runs approved catalog actions as child processes with timeouts.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{CatalogAction, Finding, JobState, JobStatus};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::{watch, Semaphore};

use crate::parsers;

const LOG_LINES: usize = 2000;
const MAX_STDOUT: usize = 64 * 1024 * 1024;
const MAX_OUTPUT_FILE: u64 = 256 * 1024 * 1024;

pub struct ExecConfig {
    /// PATH given to tools; nothing else from the runner's environment is passed on.
    pub tools_path: String,
    /// Shared download cache (vulnerability databases, rule bundles) so each
    /// job doesn't fetch them again. Per-job home directories otherwise.
    pub cache_dir: Option<PathBuf>,
    /// Where the tools are installed, for `{{ tools_dir }}` (e.g. nuclei templates).
    pub tools_dir: String,
}

/// One approved action and what it runs against.
pub struct JobSpec {
    pub action: CatalogAction,
    /// Workspace directory; `src/` inside it holds the project for code actions.
    pub ws: PathBuf,
    /// Target for URL actions, already checked against the scope.
    pub url: Option<url::Url>,
    pub rate_limit_rps: u32,
}

#[derive(Default)]
struct Inner {
    status: Option<JobStatus>,
    started: Option<Instant>,
    finished: Option<Instant>,
    exit_code: Option<i32>,
    error: Option<String>,
    log: VecDeque<String>,
    findings: Vec<Finding>,
}

pub struct Job {
    id: String,
    action_id: String,
    inner: Mutex<Inner>,
    stop: watch::Sender<bool>,
}

impl Job {
    fn set(&self, f: impl FnOnce(&mut Inner)) {
        f(&mut self.inner.lock().unwrap());
    }

    pub(crate) fn log(&self, line: String) {
        let mut inner = self.inner.lock().unwrap();
        if inner.log.len() == LOG_LINES {
            inner.log.pop_front();
        }
        inner.log.push_back(line);
    }

    fn finish(&self, status: JobStatus, error: Option<String>) {
        self.set(|i| {
            i.status = Some(status);
            i.error = error;
            i.finished = Some(Instant::now());
        });
    }

    pub fn state(&self, lines: usize) -> JobState {
        let i = self.inner.lock().unwrap();
        let elapsed = match (i.started, i.finished) {
            (Some(s), Some(f)) => f - s,
            (Some(s), None) => s.elapsed(),
            _ => Duration::ZERO,
        };
        JobState {
            job_id: self.id.clone(),
            action_id: self.action_id.clone(),
            status: i.status.unwrap_or(JobStatus::Queued),
            elapsed_secs: elapsed.as_secs(),
            exit_code: i.exit_code,
            error: i.error.clone(),
            log: i
                .log
                .iter()
                .skip(i.log.len().saturating_sub(lines))
                .cloned()
                .collect(),
            findings: i.findings.clone(),
        }
    }

    pub fn request_stop(&self) {
        let _ = self.stop.send(true);
    }
}

pub struct Jobs {
    jobs: Mutex<HashMap<String, Arc<Job>>>,
    slots: Arc<Semaphore>,
    config: Arc<ExecConfig>,
}

impl Jobs {
    pub fn new(parallel: usize, config: ExecConfig) -> Self {
        Self {
            jobs: Mutex::default(),
            slots: Arc::new(Semaphore::new(parallel.max(1))),
            config: Arc::new(config),
        }
    }

    /// Forgets jobs that finished more than `max_age` ago (the app has stored their results by then).
    pub fn prune(&self, max_age: Duration) {
        self.jobs.lock().unwrap().retain(|_, job| {
            let finished = job.inner.lock().unwrap().finished;
            finished.is_none_or(|f| f.elapsed() < max_age)
        });
    }

    pub fn get(&self, id: &str) -> Option<Arc<Job>> {
        self.jobs.lock().unwrap().get(id).cloned()
    }

    /// Queues the job and returns its id.
    pub fn start(&self, spec: JobSpec) -> String {
        let id = crate::random_id();
        let (stop, stop_rx) = watch::channel(false);
        let job = Arc::new(Job {
            id: id.clone(),
            action_id: spec.action.id.clone(),
            inner: Mutex::default(),
            stop,
        });
        self.jobs.lock().unwrap().insert(id.clone(), job.clone());
        let slots = self.slots.clone();
        let config = self.config.clone();
        tokio::spawn(async move {
            let mut stop_rx = stop_rx;
            let permit = tokio::select! {
                p = slots.acquire_owned() => p.expect("semaphore open"),
                _ = stopped(&mut stop_rx) => {
                    job.finish(JobStatus::Stopped, None);
                    return;
                }
            };
            run(&job, &spec, &config, stop_rx).await;
            drop(permit);
        });
        id
    }
}

/// Resolves once a stop was requested.
async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await;
}

/// Finds the Cargo.lock closest to the project root.
fn find_cargo_lock(src: &Path) -> Option<PathBuf> {
    let mut queue = VecDeque::from([src.to_path_buf()]);
    while let Some(dir) = queue.pop_front() {
        let lock = dir.join("Cargo.lock");
        if lock.is_file() {
            return Some(lock);
        }
        let mut subdirs: Vec<PathBuf> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter(|e| {
                !matches!(
                    e.file_name().to_str(),
                    Some(".git" | "target" | "node_modules")
                )
            })
            .map(|e| e.path())
            .collect();
        subdirs.sort();
        queue.extend(subdirs);
    }
    None
}

/// Values for the `{{ … }}` placeholders in a catalog action.
struct Vars {
    src: String,
    out: String,
    url: Option<url::Url>,
    rps: u32,
    tools_dir: String,
    cargo_lock: Option<PathBuf>,
}

/// Escapes regex metacharacters, for ZAP's include-path patterns.
fn regex_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if r"\.^$|?*+()[]{}".contains(c) {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}

impl Vars {
    fn render(&mut self, template: &str, src_dir: &Path) -> Result<String, String> {
        let mut text = template
            .replace("{{ src }}", &self.src)
            .replace("{{ out }}", &self.out);
        text = text
            .replace("{{ rps }}", &self.rps.to_string())
            .replace("{{ delay_ms }}", &(1000 / self.rps.max(1)).to_string())
            .replace("{{ tools_dir }}", &self.tools_dir);
        if text.contains("{{ url") || text.contains("{{ origin_regex_q }}") {
            let url = self.url.as_ref().ok_or("This action needs a target URL")?;
            let origin = url.origin().ascii_serialization();
            let quote = |s: &str| serde_json::to_string(s).expect("string");
            text = text
                .replace("{{ url_q }}", &quote(url.as_str()))
                .replace(
                    "{{ origin_regex_q }}",
                    &quote(&format!("{}/.*", regex_escape(&origin))),
                )
                .replace("{{ url }}", url.as_str());
        }
        if text.contains("{{ cargo_lock }}") {
            if self.cargo_lock.is_none() {
                self.cargo_lock =
                    Some(find_cargo_lock(src_dir).ok_or("No Cargo.lock found in the project")?);
            }
            text = text.replace(
                "{{ cargo_lock }}",
                &self.cargo_lock.as_ref().unwrap().to_string_lossy(),
            );
        }
        if let Some(i) = text.find("{{") {
            return Err(format!(
                "Unsupported placeholder in {}",
                &text[i..text.len().min(i + 30)]
            ));
        }
        Ok(text)
    }
}

/// Shortens absolute workspace paths in log lines.
fn tidy(line: &str, src: &str, ws: &str) -> String {
    line.replace(&format!("{src}/"), "")
        .replace(src, ".")
        .replace(&format!("{ws}/"), "")
}

async fn pump(
    job: Arc<Job>,
    stream: impl AsyncRead + Unpin,
    src: String,
    ws: String,
    keep: bool,
) -> String {
    let mut lines = BufReader::new(stream).lines();
    let mut kept = String::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if keep && kept.len() + line.len() < MAX_STDOUT {
            kept.push_str(&line);
            kept.push('\n');
        }
        job.log(tidy(&line, &src, &ws));
    }
    kept
}

fn kill_group(pid: Option<u32>) {
    if let Some(pid) = pid {
        // The child leads its own process group, so this also stops its children.
        unsafe {
            libc::kill(-(pid as i32), libc::SIGKILL);
        }
    }
}

/// Runs a `builtin:<name>` action inside the runner instead of a process.
async fn run_builtin(
    job: &Arc<Job>,
    name: &str,
    url: Option<&url::Url>,
    src: &Path,
) -> Result<Vec<Finding>, String> {
    match name {
        "cors" => {
            crate::recon::cors(url.ok_or("This action needs a target URL")?, |line| {
                job.log(line)
            })
            .await
        }
        "mobile-config" => {
            let src = src.to_path_buf();
            let (findings, log) = tokio::task::spawn_blocking(move || crate::mobile::check(&src))
                .await
                .map_err(|e| e.to_string())?;
            log.into_iter().for_each(|line| job.log(line));
            Ok(findings)
        }
        other => Err(format!("Unknown built-in check {other}")),
    }
}

async fn run(job: &Arc<Job>, spec: &JobSpec, config: &ExecConfig, mut stop: watch::Receiver<bool>) {
    let action = &spec.action;
    job.set(|i| {
        i.status = Some(JobStatus::Running);
        i.started = Some(Instant::now());
    });
    let src = spec.ws.join("src");
    let out = spec.ws.join("out").join(&job.id);
    let home = out.join(".home");
    if let Err(e) = tokio::fs::create_dir_all(&home).await {
        return job.finish(
            JobStatus::Failed,
            Some(format!("Cannot create output dir: {e}")),
        );
    }
    let src_s = src.to_string_lossy().to_string();
    let ws_s = spec.ws.to_string_lossy().to_string();
    let mut vars = Vars {
        src: src_s.clone(),
        out: out.to_string_lossy().to_string(),
        url: spec.url.clone(),
        rps: spec.rate_limit_rps,
        tools_dir: config.tools_dir.clone(),
        cargo_lock: None,
    };
    let timeout = Duration::from_secs(action.timeout_minutes * 60);

    if let Some(name) = action
        .command
        .first()
        .and_then(|c| c.strip_prefix("builtin:"))
    {
        job.log(format!(
            "Built-in {name} check against {}",
            spec.url.as_ref().map_or("?", |u| u.as_str())
        ));
        let result = tokio::select! {
            r = run_builtin(job, name, spec.url.as_ref(), &src) => r,
            _ = tokio::time::sleep(timeout) => Err(format!("Timed out after {} minutes", action.timeout_minutes)),
            _ = stopped(&mut stop) => return job.finish(JobStatus::Stopped, None),
        };
        return match result {
            Ok(findings) => {
                job.log(format!("{} findings", findings.len()));
                job.set(|i| i.findings = findings);
                job.finish(JobStatus::Done, None);
            }
            Err(e) => job.finish(JobStatus::Failed, Some(e)),
        };
    }

    let args: Vec<String> = match action
        .command
        .iter()
        .map(|a| vars.render(a, &src))
        .collect()
    {
        Ok(a) => a,
        Err(e) => return job.finish(JobStatus::Failed, Some(e)),
    };
    for (name, template) in &action.files {
        let written = match vars.render(template, &src) {
            Ok(text) if !name.contains('/') && !name.starts_with('.') => {
                tokio::fs::write(out.join(name), text)
                    .await
                    .map_err(|e| e.to_string())
            }
            Ok(_) => Err(format!("Invalid file name {name}")),
            Err(e) => Err(e),
        };
        if let Err(e) = written {
            return job.finish(
                JobStatus::Failed,
                Some(format!("Cannot prepare {name}: {e}")),
            );
        }
    }
    job.log(format!("$ {}", tidy(&args.join(" "), &src_s, &ws_s)));

    let mut command = Command::new(&args[0]);
    command
        .args(&args[1..])
        .env_clear()
        .env("PATH", &config.tools_path)
        .env("HOME", &home)
        .env("LANG", "C.UTF-8")
        .env("NO_COLOR", "1");
    if let Some(cache) = &config.cache_dir {
        command
            .env("XDG_CACHE_HOME", cache)
            .env("CARGO_HOME", cache.join("cargo"))
            .env("TRIVY_CACHE_DIR", cache.join("trivy"));
    }
    let mut child = match command
        .current_dir(&out)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return job.finish(
                JobStatus::Failed,
                Some(format!("Cannot start {}: {e}", args[0])),
            )
        }
    };
    let pid = child.id();
    let needs_stdout = action.parser.is_some() && action.output.is_none();
    let stdout = tokio::spawn(pump(
        job.clone(),
        child.stdout.take().unwrap(),
        src_s.clone(),
        ws_s.clone(),
        needs_stdout,
    ));
    let stderr = tokio::spawn(pump(
        job.clone(),
        child.stderr.take().unwrap(),
        src_s.clone(),
        ws_s.clone(),
        false,
    ));

    let exit = tokio::select! {
        status = child.wait() => status.ok(),
        _ = tokio::time::sleep(timeout) => {
            kill_group(pid);
            let _ = child.wait().await;
            return job.finish(JobStatus::Failed, Some(format!("Timed out after {} minutes", action.timeout_minutes)));
        }
        _ = stopped(&mut stop) => {
            kill_group(pid);
            let _ = child.wait().await;
            return job.finish(JobStatus::Stopped, None);
        }
    };
    kill_group(pid);
    let stdout = stdout.await.unwrap_or_default();
    let _ = stderr.await;
    let code = exit.and_then(|s| s.code());
    job.set(|i| i.exit_code = code);

    if !code.is_some_and(|c| action.ok_exit_codes.contains(&c)) {
        let how = code.map_or_else(
            || "was killed".to_string(),
            |c| format!("exited with code {c}"),
        );
        return job.finish(
            JobStatus::Failed,
            Some(format!("{} {how}; see the log", action.tool)),
        );
    }
    let Some(parser) = &action.parser else {
        return job.finish(JobStatus::Done, None);
    };
    let data = match &action.output {
        Some(path) => {
            let path = PathBuf::from(path.replace("{{ out }}", &out.to_string_lossy()));
            match tokio::fs::metadata(&path).await {
                Ok(m) if m.len() > MAX_OUTPUT_FILE => Err("Result file is too large".to_string()),
                Ok(_) => tokio::fs::read_to_string(&path)
                    .await
                    .map_err(|e| e.to_string()),
                Err(_) => Err(format!("{} wrote no results", action.tool)),
            }
        }
        None => Ok(stdout),
    };
    let default_location = match &spec.url {
        Some(url) => Some(url.to_string()),
        None => vars.cargo_lock.as_ref().map(|p| {
            p.strip_prefix(&src)
                .unwrap_or(p)
                .to_string_lossy()
                .to_string()
        }),
    };
    let ctx = parsers::Context {
        tool: &action.tool,
        src: &src_s,
        severity: action.severity,
        default_location,
    };
    match data.and_then(|d| parsers::parse(parser, &d, &ctx)) {
        Ok(findings) => {
            job.log(format!("{} findings", findings.len()));
            job.set(|i| i.findings = findings);
            job.finish(JobStatus::Done, None);
        }
        Err(e) => job.finish(JobStatus::Failed, Some(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(
        command: &[&str],
        parser: Option<&str>,
        output: Option<&str>,
        timeout_minutes: u64,
    ) -> CatalogAction {
        CatalogAction {
            id: "t".into(),
            title: "t".into(),
            tool: "t".into(),
            input: "source".into(),
            mode: "passive".into(),
            est_minutes: 1,
            command: command.iter().map(|s| s.to_string()).collect(),
            parser: parser.map(str::to_string),
            output: output.map(str::to_string),
            timeout_minutes,
            severity: None,
            ok_exit_codes: vec![0, 1],
            files: Default::default(),
        }
    }

    fn spec(action: CatalogAction, ws: &Path) -> JobSpec {
        JobSpec {
            action,
            ws: ws.to_path_buf(),
            url: None,
            rate_limit_rps: 10,
        }
    }

    async fn wait(jobs: &Jobs, id: &str) -> JobState {
        for _ in 0..200 {
            let state = jobs.get(id).unwrap().state(100);
            if state.status.is_finished() {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("job did not finish");
    }

    fn setup(cache_dir: Option<PathBuf>) -> (tempfile::TempDir, Jobs) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("src/sub")).unwrap();
        let config = ExecConfig {
            tools_path: "/usr/bin:/bin".into(),
            cache_dir,
            tools_dir: "/opt/tools".into(),
        };
        (tmp, Jobs::new(1, config))
    }

    #[tokio::test]
    async fn runs_tool_and_parses_output_file() {
        let (tmp, jobs) = setup(None);
        let sarif = r#"{"runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","level":"error","message":{"text":"bad"}}]}]}"#;
        let script = format!("echo running; echo '{sarif}' > \"$1/r.sarif\"; exit 1");
        let a = action(
            &["sh", "-c", &script, "sh", "{{ out }}"],
            Some("sarif"),
            Some("{{ out }}/r.sarif"),
            1,
        );
        let id = jobs.start(spec(a, tmp.path()));
        let state = wait(&jobs, &id).await;
        assert_eq!(state.status, JobStatus::Done, "{state:?}");
        assert_eq!(state.exit_code, Some(1));
        assert_eq!(state.findings.len(), 1);
        assert!(state.log.iter().any(|l| l == "running"));
    }

    #[tokio::test]
    async fn unexpected_exit_code_fails_even_with_results() {
        let (tmp, jobs) = setup(None);
        let script = "echo '{\"runs\":[]}' > \"$1/r.sarif\"; exit 127";
        let a = action(
            &["sh", "-c", script, "sh", "{{ out }}"],
            Some("sarif"),
            Some("{{ out }}/r.sarif"),
            1,
        );
        let state = wait(&jobs, &jobs.start(spec(a, tmp.path()))).await;
        assert_eq!(state.status, JobStatus::Failed);
        assert_eq!(
            state.error.as_deref(),
            Some("t exited with code 127; see the log")
        );
    }

    #[tokio::test]
    async fn only_path_home_and_cache_reach_tools() {
        let (tmp, jobs) = setup(Some(PathBuf::from("/var/cache/x")));
        std::env::set_var("RUNNER_TOKEN_TEST_SECRET", "s3cret");
        let id = jobs.start(spec(
            action(&["sh", "-c", "env"], None, None, 1),
            tmp.path(),
        ));
        let state = wait(&jobs, &id).await;
        assert!(!state.log.iter().any(|l| l.contains("s3cret")));
        assert!(
            state
                .log
                .iter()
                .any(|l| l == "CARGO_HOME=/var/cache/x/cargo"),
            "{:?}",
            state.log
        );
    }

    #[tokio::test]
    async fn renders_url_rate_limit_and_plan_files() {
        let (tmp, jobs) = setup(None);
        let mut a = action(
            &[
                "sh",
                "-c",
                "cat plan.yaml; echo \"$1 $2\"",
                "sh",
                "{{ url }}",
                "{{ rps }}",
            ],
            None,
            None,
            1,
        );
        a.files.insert(
            "plan.yaml".into(),
            "urls: [{{ url_q }}]\ninclude: {{ origin_regex_q }}\ndelay: {{ delay_ms }}\n".into(),
        );
        let mut s = spec(a, tmp.path());
        s.url = Some(url::Url::parse("https://test.example.dk/a?b=\"c\"").unwrap());
        s.rate_limit_rps = 4;
        let state = wait(&jobs, &jobs.start(s)).await;
        assert_eq!(state.status, JobStatus::Done, "{state:?}");
        assert!(
            state
                .log
                .contains(&r#"urls: ["https://test.example.dk/a?b=%22c%22"]"#.to_string()),
            "{:?}",
            state.log
        );
        assert!(
            state
                .log
                .contains(&r#"include: "https://test\\.example\\.dk/.*""#.to_string()),
            "{:?}",
            state.log
        );
        assert!(state.log.contains(&"delay: 250".to_string()));
        assert!(state
            .log
            .contains(&"https://test.example.dk/a?b=%22c%22 4".to_string()));
    }

    #[tokio::test]
    async fn url_placeholder_without_url_fails() {
        let (tmp, jobs) = setup(None);
        let state = wait(
            &jobs,
            &jobs.start(spec(
                action(&["echo", "{{ url }}"], None, None, 1),
                tmp.path(),
            )),
        )
        .await;
        assert_eq!(
            state.error.as_deref(),
            Some("This action needs a target URL")
        );
    }

    #[tokio::test]
    async fn stop_kills_running_job() {
        let (tmp, jobs) = setup(None);
        let id = jobs.start(spec(action(&["sleep", "30"], None, None, 1), tmp.path()));
        tokio::time::sleep(Duration::from_millis(100)).await;
        jobs.get(&id).unwrap().request_stop();
        assert_eq!(wait(&jobs, &id).await.status, JobStatus::Stopped);
    }

    #[tokio::test]
    async fn missing_cargo_lock_fails_clearly() {
        let (tmp, jobs) = setup(None);
        let a = action(
            &["cargo-audit", "--file", "{{ cargo_lock }}"],
            Some("cargo-audit"),
            None,
            1,
        );
        let state = wait(&jobs, &jobs.start(spec(a, tmp.path()))).await;
        assert_eq!(state.status, JobStatus::Failed);
        assert_eq!(
            state.error.as_deref(),
            Some("No Cargo.lock found in the project")
        );
    }

    #[test]
    fn finds_nearest_cargo_lock() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("a/b")).unwrap();
        std::fs::write(tmp.path().join("a/b/Cargo.lock"), "").unwrap();
        std::fs::write(tmp.path().join("a/Cargo.lock"), "").unwrap();
        assert_eq!(
            find_cargo_lock(tmp.path()),
            Some(tmp.path().join("a/Cargo.lock"))
        );
    }
}
