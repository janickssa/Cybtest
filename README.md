# SecTestGen

A personal, self-hosted web tool for security testing your own apps and websites. Give it a **project `.zip`**, an **internal URL** (e.g. `https://internaltest.schwabejss.dk`), a **description**, or any combination, and it will:

1. **Analyze** the target and detect the tech stack (languages, frameworks, dependencies, server software).
2. **Suggest** a security test plan: which tools and checks to run, and why.
3. **Wait for your approval.** Nothing runs until you approve it, test by test.
4. **Run** the approved tests in an isolated runner and show live progress.
5. **Report** findings in one place, with export to Markdown, JSON and SARIF.

Recommendations come from a **hybrid engine**: a curated rule base (mapped to OWASP standards) for reliable baseline tests, plus an AI layer for extra, context-specific suggestions. The AI provider is swappable: **Claude**, **OpenAI**, or a **locally hosted model** (Ollama, llama.cpp, LM Studio, vLLM).

> ⚠️ **Authorized use only.** Only scan systems you own or have explicit written permission to test. The tool enforces a target allowlist (see [Scope and safety](#scope-and-safety)).

---

## Features

- **Three input types**, usable together:
  - **Project upload (`.zip`):** source code is unpacked safely and analyzed from manifests and lockfiles. Project code is **never built or executed**.
  - **Target URL:** internal or staging sites are fingerprinted passively (headers, TLS, known paths) to detect server software and frameworks.
  - **Description and tags:** free text or picked tags, for when you don't have code or a running instance.
- **Explainable detection:** every detected technology shows its evidence (e.g. "`actix-web` found in `backend/Cargo.lock`").
- **Hybrid recommendations:** rules mapped to OWASP WSTG, ASVS and MASVS, plus labeled AI suggestions.
- **Approve-then-run:** see the exact tool, command, target, mode (passive/active) and estimated time before anything runs.
- **Isolated execution** in a separate runner container with resource limits and timeouts.
- **Unified findings view:** results from all tools are normalized, deduplicated and sorted by severity, with remediation advice.
- **Compare runs:** see what's new, fixed or unchanged since the last scan.
- **Export:** findings as Markdown, JSON or SARIF; the test plan and scripts as `.zip` for running manually.
- **Project history:** re-run the same plan after fixing issues with one click.

---

## User interface

The goal: **from upload to approved scan in under a minute**, without needing to know tool names or OWASP IDs.

### Guided 4-step flow

```
 ① Add target  ──▶  ② Review & approve  ──▶  ③ Run  ──▶  ④ Results
```

**Step 1: Add target**

```
┌──────────────────────────────────────────────────────────────┐
│  Project: [ Webshop API                ]                     │
│                                                              │
│  [ 📦 Upload project ]  [ 🌐 Target URL ]  [ ✏️ Describe ]     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │      Drop project.zip here or click to browse          │  │
│  │                   (max 200 MB)                         │  │
│  └────────────────────────────────────────────────────────┘  │
│  ✅ project.zip  (38 MB, 1 204 files)                        │
│                                                              │
│  🌐 https://internaltest.schwabejss.dk   ✅ in allowlist     │
│                                                              │
│                                   [ Analyze → ]              │
└──────────────────────────────────────────────────────────────┘
```

After analysis, a summary shows what was found:

```
  Detected stack
  [Rust ✕]  [Actix-web ✕]  [sqlx/PostgreSQL ✕]  [jsonwebtoken ✕]
  [React ✕] [Docker ✕]     [nginx 1.24 ✕]       + Add tag

  ▸ Why?  actix-web 4.9 → backend/Cargo.lock
          Server: nginx/1.24 → HTTP header from internaltest.schwabejss.dk
```

You can remove wrong tags or add missing ones before continuing.

**Step 2: Review & approve**

```
┌──────────────────────────────────────────────────────────────┐
│  14 tests suggested        Filter: [All ▾]   🔍 Search        │
│                                                              │
│  RUN AUTOMATICALLY                                           │
│  ☑ 🔴 Vulnerable Rust crates      cargo-audit  Code  ~1 min ▸│
│  ☑ 🔴 Secrets in source code      gitleaks     Code  ~1 min ▸│
│  ☑ 🔴 SQL injection patterns      semgrep      Code  ~3 min ▸│
│  ☑ 🟠 Security headers & TLS      zap/testssl  URL   ~5 min ▸│
│  ☐ 🔴 Active web scan  ⚡ACTIVE    zap active   URL  ~40 min ▸│
│                                                              │
│  MANUAL / EXPORT ONLY                                        │
│  ☑ 🟠 Panics on malformed input  ✨ AI  script for review   ▸│
│                                                              │
│  [ ← Back ]     5 selected · ~10 min   [ Approve & run → ]   │
└──────────────────────────────────────────────────────────────┘
```

- Each row shows severity, title, tool, input (Code or URL), and estimated time.
- Expanding a row shows *why* it's suggested, the **exact command** that will run, and the target.
- **Passive** tests are pre-selected. **Active** tests (which send attack payloads to the URL) are never pre-selected, are marked ⚡, and require typing the hostname to confirm.
- AI suggestions that need custom code are **export-only**: they can't be run from the UI in v1.

**Step 3: Run**

- A live list of jobs with status (queued, running, done, failed), elapsed time and a progress bar.
- Click a job to see its live log output.
- A **Stop** button per job and a **Stop all** button.
- Findings appear in a counter as they arrive ("3 high, 7 medium so far").

**Step 4: Results**

```
┌──────────────────────────────────────────────────────────────┐
│  Run #4 · 12 findings   🔴 3  🟠 5  🟡 4    vs run #3: 2 new, 4 fixed │
│                                                              │
│  🔴 RUSTSEC-2024-xxxx in `sqlx 0.7.1`     cargo-audit  NEW   ▸│
│  🔴 Hardcoded AWS key  config/dev.rs:14   gitleaks           ▸│
│  🟠 Missing Content-Security-Policy       zap                ▸│
│                                                              │
│  [ Export ▾ ]  Markdown · JSON · SARIF · Raw logs            │
└──────────────────────────────────────────────────────────────┘
```

- Each finding expands to: description, evidence (file and line, or URL and response), how to fix it, and references.
- Mark findings as **false positive** or **accepted risk** so they're hidden in future runs.
- **Re-run** repeats the same approved plan with one click.

### Other screens

- **Projects:** saved projects with stack tags, last run and finding counts.
- **Settings:** target allowlist, AI provider and model (with **"Test connection"**), what is sent to the AI, scan limits, runner status, password and theme.

### Usability principles

- **Plain language first.** OWASP IDs and tool names are shown as small badges, never as the main label.
- **One obvious next step.** Each screen has a single primary button.
- **Safe by default.** Passive tests pre-selected, active tests opt-in with confirmation.
- **Sensible defaults.** Works without configuration in rules-only mode.
- **Clear feedback.** Visible loading states, and if the AI or a tool fails, everything else still works with a friendly notice.
- **Responsive**, **light and dark mode**, **keyboard shortcuts** (`Ctrl+Enter` to continue, `/` to search, `Space` to toggle a test) and **accessible** (WCAG 2.1 AA as the target).

---

## How it works

```
                 ┌───────────────────────────────┐      ┌──────────────────────────────┐
 ┌──────────┐    │  App container (LXC)          │      │  Runner container (LXC)      │
 │  Web UI  │───▶│                               │ jobs │                              │
 └──────────┘    │  1. Store upload / URL        │─────▶│  a. Unpack zip safely        │
                 │  4. Rule engine ─▶ rules/     │      │  b. Detect stack             │──▶ internal URL
                 │  5. AI layer ─▶ Claude/OpenAI/│◀─────│  c. Run approved tool jobs   │    (allowlisted)
                 │                 local         │ logs │  d. Parse output → findings  │
                 │  6. Plan → your approval      │ +    │                              │
                 │  7. Findings DB + reports     │result│  Tools: semgrep, gitleaks,   │
                 │                               │      │  osv-scanner, cargo-audit,   │
                 │  SQLite · serves frontend     │      │  trivy, ZAP, nuclei, testssl │
                 └───────────────────────────────┘      └──────────────────────────────┘
```

1. **Input** – the zip is stored on the app container and streamed to the runner. The app never unpacks untrusted archives itself.
2. **Analysis** (runner) – the zip is unpacked into a per-run workspace and the stack is detected from manifest files. For URLs, a passive fingerprint is taken.
3. **Tags** – detection results are turned into normalized tags with evidence (`lang:rust`, `crate:actix-web`, `server:nginx`).
4. **Rule engine** – rules map tags to tests and tool actions. Deterministic and offline.
5. **AI layer** – sends a summary to the configured AI provider and asks for *additional* tests. AI can only pick from the tool catalog (see below) and never removes rule-based tests.
6. **Approval** – the merged plan is shown to you. Only approved jobs are sent to the runner.
7. **Execution and results** – the runner executes each job with limits, streams logs back, parses tool output (mostly SARIF/JSON) into normalized findings, and the app stores them.

### Stack detection

| File found | Detected |
|---|---|
| `Cargo.toml`, `Cargo.lock` | Rust + crates (e.g. actix-web, axum, sqlx, diesel, jsonwebtoken) |
| `package.json`, lockfiles | Node.js + React, Next.js, Express, etc. |
| `requirements.txt`, `pyproject.toml`, `poetry.lock` | Python + Django, Flask, FastAPI |
| `composer.json` | PHP + Laravel, Symfony, WordPress |
| `pom.xml`, `build.gradle` | Java/Kotlin + Spring |
| `go.mod` | Go + frameworks |
| `Dockerfile`, `docker-compose.yml` | Containers, base images, exposed ports |
| `*.tf`, Kubernetes YAML | Infrastructure as code |
| `AndroidManifest.xml`, `Info.plist` | Mobile apps (MASVS rules) |
| `.github/workflows`, `.gitlab-ci.yml` | CI/CD pipelines |

File extensions are also counted to detect languages without manifests.

### Tool catalog

The runner can only execute **predefined actions** from a catalog. Neither the AI nor the uploaded project can introduce new commands. Each action is a YAML file:

```yaml
id: semgrep-scan
title: Static code analysis
tool: semgrep
input: source            # source | url
mode: passive            # passive | active
command: ["semgrep", "scan", "--config", "{{ ruleset }}",
          "--sarif", "--output", "{{ out }}/semgrep.sarif", "{{ src }}"]
params:
  ruleset:
    type: enum
    values: [p/default, p/rust, p/javascript, p/python, p/owasp-top-ten]
limits:
  timeout_minutes: 20
  memory_mb: 2048
parser: sarif
```

Commands are run as an argument list, never through a shell, and parameters are validated against their type (enums, URLs from the project scope, etc.).

**Initial catalog:**

| Action | Tool | Input | Mode |
|---|---|---|---|
| Static code analysis | Semgrep | Code | Passive |
| Secrets in code | gitleaks | Code | Passive |
| Vulnerable dependencies (all ecosystems) | osv-scanner | Code | Passive |
| Vulnerable Rust crates | cargo-audit | Code | Passive |
| Dockerfile / IaC misconfiguration | Trivy (config) | Code | Passive |
| Baseline web scan (headers, cookies, info leaks) | OWASP ZAP baseline | URL | Passive |
| TLS configuration | testssl.sh | URL | Passive |
| Known misconfigurations and exposures | nuclei (safe templates) | URL | Passive |
| JWT, CORS and auth checks | Built-in Python checks | URL | Passive / Active |
| Full active web scan | OWASP ZAP active scan | URL | **Active** |

Dependency scanners read lockfiles only. Commands like `npm install`, `cargo build` or running the project's tests are deliberately **not** in the catalog, because they would execute code from the upload.

---

## Example

**Input:** `project.zip` (Rust/Actix backend + React frontend) and `https://internaltest.schwabejss.dk`

**Detected:** Rust, actix-web 4.9, sqlx (PostgreSQL), jsonwebtoken, React 18, Dockerfile (debian:12-slim), nginx 1.24 (from HTTP headers).

**Suggested plan (excerpt):**

| Priority | Test | Why | Action |
|---|---|---|---|
| High | Vulnerable crates | `Cargo.lock` found | cargo-audit |
| High | Secrets in source | Always for code uploads | gitleaks |
| High | SQL injection in raw `sqlx::query` | sqlx + string formatting detected | Semgrep (custom rule) |
| High | JWT validation weaknesses | jsonwebtoken crate | Built-in JWT checks |
| Medium | Security headers, cookies | URL given | ZAP baseline |
| Medium | TLS configuration | HTTPS URL | testssl.sh |
| Medium | Base image vulnerabilities | Dockerfile found | Trivy |
| Optional | Full active scan | URL given | ZAP active ⚡ |

**AI suggestion (export-only):** "Check for panics on malformed JSON bodies that could crash Actix workers (denial of service)", with a fuzzing script for manual review.

---

## Scope and safety

Running real scans means the tool itself must be careful. These protections are built in, not optional.

**Target allowlist**
- Settings contain the hosts and networks you may scan, e.g. `*.schwabejss.dk` and `10.0.20.0/24`.
- A URL outside the allowlist can still be used to *generate* a plan, but its jobs can't be run.
- The hostname is resolved and the IP is checked against allowed networks right before each job (prevents DNS tricks pointing an allowed name at another host).
- The runner enforces the allowlist too, so a bug in the app can't bypass it.

**Passive vs active**
- **Passive** tests only send normal requests (like a browser would) or only read code.
- **Active** tests send attack payloads and can change data or cause load. They are opt-in, require typing the hostname to confirm, and should be run against test/staging environments.
- Default rate limit for URL tests: **10 requests per second**, adjustable per project.

**Uploaded archives** (treated as untrusted)
- Max upload 200 MB, max unpacked size 2 GB, max 100 000 files, and a compression ratio check to stop zip bombs.
- Paths with `..` or absolute paths are rejected (prevents "zip slip"), symlinks are skipped, and executable permissions are removed.
- Unpacked into a per-run workspace that tools can only read. Workspaces are deleted after **7 days** (configurable).
- Project code is never built, installed or executed.

**AI and untrusted content**
- Uploaded code may contain text that tries to manipulate the AI ("ignore your instructions and…"). That's why AI output is only accepted as structured JSON choosing catalog actions with validated parameters, and targets always come from the project, never from the AI.
- **What is sent to the AI** is configurable: *summary only* (tags, dependency names and versions, file tree) is the default for cloud providers; *selected files* is available and is the default for the local provider. Source code never leaves your network unless you allow it.

**Runner isolation**
- Each job runs as a dedicated unprivileged user via a `systemd-run` transient unit with memory, CPU and time limits.
- The runner container has a firewall allowing outgoing traffic only to allowlisted targets and the tools' update sources (vulnerability databases).
- The runner can be snapshotted and rolled back at any time, since it holds no permanent data.

---

## AI providers

All providers implement one Rust trait, so the rest of the app doesn't care which one is active:

```rust
#[async_trait]
pub trait AiProvider {
    async fn suggest_tests(&self, req: &SuggestRequest) -> Result<Vec<SuggestedTest>>;
}
```

| Provider | `AI_PROVIDER` | Notes |
|---|---|---|
| Anthropic Claude | `anthropic` | Messages API |
| OpenAI | `openai` | Chat Completions / Responses API with JSON output |
| Local | `local` | Any OpenAI-compatible server: Ollama, llama.cpp server, LM Studio, vLLM |
| None | `none` | Rules-only mode |

```bash
AI_PROVIDER=local            # anthropic | openai | local | none
AI_MODEL=qwen2.5:14b         # model name for the chosen provider
AI_SEND=summary              # summary | selected_files

ANTHROPIC_API_KEY=
OPENAI_API_KEY=
LOCAL_BASE_URL=http://<ollama-lxc-ip>:11434/v1
```

The provider and model can be switched per run in the UI. Every AI response is validated against the `SuggestedTest` schema; if parsing fails, it's retried once, then the run continues with rule-based results and a warning. A local model of roughly 7B parameters or larger is recommended.

---

## Rule format

Rules live in `rules/` as YAML and link detected tags to catalog actions and manual tests.

```yaml
id: jwt-weak-validation
title: JWT validation weaknesses
when:
  any: [auth:jwt, crate:jsonwebtoken, npm:jsonwebtoken]
severity: high
references: [WSTG-SESS-10, ASVS-3.5]
description: >
  Verify the server rejects tokens with alg "none", tokens signed with a
  different key, expired tokens, and tokens with tampered claims.
expected_secure_behavior: All manipulated tokens return 401.
actions:
  - id: builtin-jwt-checks          # runnable, needs a URL
    requires: [url]
export_scripts:
  - template: templates/python/jwt_checks.py.j2
```

`when` supports `all`, `any` and `none`, e.g. "Rust **and** raw SQL **but not** an ORM".

---

## Tech stack

- **Frontend:** React + Vite + Tailwind, shadcn/ui components, TanStack Query, Server-Sent Events for live job logs, and a syntax highlighter for commands and scripts
- **Backend (app):** Rust + Axum on Tokio, serving both the API and the built frontend
- **Runner:** separate Rust binary (also Axum), authenticated to the app with a shared token over HTTPS
- **Archives:** `zip` crate with safe path handling (`enclosed_name`)
- **Serialization:** Serde (JSON for the API, YAML for rules and catalog)
- **Findings:** parsers for SARIF and each tool's JSON output, normalized into one `Finding` struct
- **Storage:** SQLite via `sqlx`
- **Templates:** `minijinja` for export scripts
- **AI:** provider-agnostic layer using `reqwest`
- **Deployment:** two LXC containers (app + runner), systemd services

---

## Project structure

```
sectestgen/
├── Cargo.toml                 # workspace
├── crates/
│   ├── common/                # shared types: Job, Finding, Tag, catalog schema
│   ├── app/
│   │   ├── src/
│   │   │   ├── main.rs        # Axum entrypoint + routes
│   │   │   ├── auth.rs        # single-user login
│   │   │   ├── projects.rs    # projects, uploads, history
│   │   │   ├── scope.rs       # target allowlist checks
│   │   │   ├── rules.rs       # rule engine
│   │   │   ├── ai/            # AiProvider trait + anthropic, openai, local
│   │   │   ├── plan.rs        # merge, rank, approval state
│   │   │   ├── jobs.rs        # dispatch to runner, live log stream
│   │   │   ├── findings.rs    # storage, dedupe, run comparison
│   │   │   ├── export/        # Markdown, JSON, SARIF, script zip
│   │   │   └── db.rs
│   │   └── migrations/
│   └── runner/
│       └── src/
│           ├── main.rs        # job API
│           ├── unpack.rs      # safe zip extraction
│           ├── detect.rs      # stack detection from files
│           ├── recon.rs       # passive URL fingerprinting
│           ├── execute.rs     # tool processes with timeouts, clean environment
│           ├── scope.rs       # second allowlist check
│           └── parsers.rs     # SARIF, cargo-audit JSON → findings
├── frontend/                  # React UI
├── rules/                     # YAML rule base
├── catalog/                   # YAML tool actions
├── templates/                 # export script templates (.j2)
├── deploy/
│   ├── app/                   # systemd unit + install.sh
│   └── runner/                # systemd unit + install.sh + install-tools.sh
└── README.md
```

---

## Deployment: LXC containers

Two unprivileged LXC containers (e.g. on Proxmox). The app container is small and holds all data; the runner does the risky and heavy work and holds nothing permanent.

| | App container | Runner container |
|---|---|---|
| Template | Debian 12 / Ubuntu 24.04 | Debian 12 / Ubuntu 24.04 |
| CPU | 1 core | 2–4 cores |
| RAM | 1 GB | 4 GB (ZAP alone uses about 2 GB) |
| Disk | 10 GB (uploads, results) | 20 GB (tools, vulnerability databases, workspaces) |
| Network | Reachable from your machine | Reaches allowlisted targets; only the app may connect to it |
| Contains | Binary, frontend, SQLite, rules, catalog | Runner binary + scanning tools |

**Build** on your workstation or CI (compiling Rust needs about 2 GB RAM or more):

```bash
cd frontend && npm run build
cargo build --release            # → target/release/sectestgen-app, sectestgen-runner
```

**Install the app container:**

```bash
scp target/release/sectestgen-app root@<app-ip>:/usr/local/bin/
scp -r frontend/dist rules catalog templates deploy/app root@<app-ip>:/opt/sectestgen/
ssh root@<app-ip> 'bash /opt/sectestgen/app/install.sh'
```

**Install the runner container:**

```bash
scp target/release/sectestgen-runner root@<runner-ip>:/usr/local/bin/
scp -r catalog deploy/runner root@<runner-ip>:/opt/sectestgen-runner/
ssh root@<runner-ip> 'bash /opt/sectestgen-runner/runner/install.sh'
```

The runner install generates a TLS certificate and a random token, then prints the two commands that connect the app to it (copy `cert.pem` to the app, then run `deploy/app/connect-runner.sh`).

`install-tools.sh` (called by the runner install) installs Semgrep, gitleaks, osv-scanner, cargo-audit, Trivy, nuclei (plus its templates) and OWASP ZAP at pinned versions and checks each download's SHA-256. testssl.sh and Java (for ZAP) come from the distribution's packages.

**Target allowlist:** both containers read `SCOPE_ALLOWLIST` from their env file (the install scripts ask for it), e.g. `SCOPE_ALLOWLIST=*.schwabejss.dk,10.0.20.0/24`. Keep the two lists identical; the runner refuses anything outside its own list even if the app asks. When networks are listed, every address a hostname resolves to must be inside one; without networks, loopback and link-local addresses are refused. To scan a site on the runner itself (e.g. a local test), list `127.0.0.1/32` explicitly.

**Rate limits:** URL tests default to 10 requests per second (`DEFAULT_RATE_LIMIT_RPS`), adjustable per project in step 1 up to `MAX_RATE_LIMIT_RPS`. nuclei uses it directly (`-rl`) and the active ZAP scan as a delay between requests; ZAP's crawler uses two threads and testssl.sh makes a fixed, small number of TLS connections.

Scans run as the runner's own unprivileged user with a timeout per tool and an empty environment (only `PATH`, `HOME` and cache paths), so the runner's token never reaches a tool. The systemd unit caps memory and process count for the runner and all scans together.

**App settings** (`/etc/sectestgen/sectestgen.env`, permissions `600`):

```bash
BIND_ADDR=0.0.0.0:8080
DATABASE_URL=sqlite:///var/lib/sectestgen/sectestgen.db
DATA_DIR=/var/lib/sectestgen
RUNNER_URL=https://<runner-ip>:9090
RUNNER_TOKEN=<long random secret>
AUTH_PASSWORD_HASH=<argon2 hash>
MAX_UPLOAD_MB=200
WORKSPACE_RETENTION_DAYS=7
DEFAULT_RATE_LIMIT_RPS=10
```

**Internal DNS:** the runner must be able to resolve and reach internal names like `internaltest.schwabejss.dk`, so give it your internal DNS server and a network/VLAN with access to the test environment.

**Local AI:** run Ollama in a third container or VM (roughly 8–16 GB RAM for a 7–14B model, or GPU passthrough) and set `LOCAL_BASE_URL`.

**Database:** projects, runs, triage decisions and the audit log live in one SQLite file (`DATABASE_URL`), created on first start. Uploaded code stays on the runner and expires with its workspace (`WORKSPACE_RETENTION_DAYS`); re-running an old project after that asks you to upload it again.

**Backups:** only the app container needs backing up (`/var/lib/sectestgen/` and the env file). The runner can be recreated from the install script.

**Simpler alternative:** app and runner can run in the same container for a quick start, but you lose the isolation between your data and the untrusted uploads, so two containers are recommended.

### Development

```bash
cp .env.example .env
# Put a password hash in .env:
echo "AUTH_PASSWORD_HASH='$(cargo run -q -p app -- hash-password 'my password')'" >> .env
set -a && . ./.env && set +a && cargo run -p app   # API on http://localhost:8080
cd frontend && npm install && npm run dev          # UI on http://localhost:5173 (proxies /api)
cargo test                                         # rules, plan builder, login
```

Or run the UI from the app itself: `cd frontend && npm run build`, then open http://localhost:8080.

To run scans locally, start the runner too. It needs the tools on its `TOOLS_PATH`
(`TOOLS_DIR=$PWD/.tools bash deploy/runner/install-tools.sh` installs them without root):

```bash
export RUNNER_TOKEN=$(openssl rand -hex 32)
RUNNER_TOKEN=$RUNNER_TOKEN TOOLS_PATH=$PWD/.tools/bin:/usr/bin:/bin cargo run -p runner   # http://127.0.0.1:9090
RUNNER_URL=http://127.0.0.1:9090 RUNNER_TOKEN=$RUNNER_TOKEN cargo run -p app             # in another shell, with the .env above
```

Without `TLS_CERT`/`TLS_KEY` the runner serves plain HTTP; that's for local development only.

---

## Security of the tool itself

- **Single-user login** (Argon2 password hash, session cookie with `HttpOnly`, `Secure`, `SameSite=Strict`) and CSRF protection.
- Restrict port 8080 with the LXC/Proxmox firewall to your own machine or VPN; use a reverse proxy with HTTPS (e.g. Caddy) for access outside your LAN.
- App ↔ runner traffic uses HTTPS and a shared token; the runner only accepts connections from the app's IP.
- Both containers are unprivileged, services run as dedicated non-root users with hardened systemd units.
- API keys live only in env files and are never sent to the frontend.
- An **audit log** records every approval and run: who, what, which target, when.
- See [Scope and safety](#scope-and-safety) for allowlist, upload and runner protections.

---

## Roadmap

**Phase 1 – Plan generator (MVP)**
- [x] Wizard UI, tags, description input, ~30 rules, Markdown export
- [x] Single-user login, LXC install for the app container

**Phase 2 – Code uploads**
- [x] Runner container with safe zip extraction and stack detection
- [x] Passive code actions: Semgrep, gitleaks, osv-scanner, cargo-audit, Trivy
- [x] Approve-and-run flow, live logs, findings view

**Phase 3 – URL targets**
- [x] Allowlist and scope enforcement in app and runner
- [x] Passive URL actions: fingerprinting, ZAP baseline, testssl.sh, nuclei (safe)
- [x] Active ZAP scan with confirmation and rate limits

**Phase 4 – History and polish**
- [x] Saved projects and run history (SQLite), surviving restarts
- [x] Run comparison: new, fixed and unchanged findings since the last run
- [x] Mark findings as false positive or accepted risk, hidden in later runs
- [x] SARIF export
- [x] Mobile rules (MASVS) and Android/iOS project detection

**Phase 5 – Later**
- [ ] AI suggestions (Claude / OpenAI / local) with configurable data sharing
- [ ] Authenticated scanning (login sessions for URL tests)
