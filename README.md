# SecTestGen

A personal web tool that turns a description of an app or website ("Rust backend with Actix, PostgreSQL, JWT auth, React frontend") into a **security test plan** plus **runnable test scripts and tool configs**.

Recommendations come from a **hybrid engine**: a curated rule base (mapped to OWASP standards) provides reliable, repeatable baseline tests, and an AI layer suggests extra, context-specific tests the rules don't cover. The AI provider is swappable: **Claude**, **OpenAI**, or a **locally hosted model** (Ollama, llama.cpp, LM Studio, vLLM).

> ⚠️ **Authorized use only.** Only run generated tests against systems you own or have explicit written permission to test.

---

## Features

- **Describe your target** in free text, by picking tech tags (languages, frameworks, databases, auth methods, hosting), or both.
- **Pick specific tests manually** in addition to (or instead of) recommendations.
- **Rule-based recommendations** mapped to OWASP WSTG (web), ASVS (verification requirements) and MASVS (mobile).
- **AI suggestions** that read your description and propose additional tests, each clearly labeled as AI-generated with reasoning.
- **Two outputs per run:**
  - A **test plan**: prioritized checklist with what to test, why, how, and expected secure behavior.
  - **Scripts and configs**: ready-to-run files for common tools (see below).
- **Project history**: save targets and re-generate when the stack changes.
- **Export** the plan as Markdown and the scripts as a `.zip`.

---

## How it works

```
 ┌──────────────┐     ┌──────────────────┐
 │  Web UI      │────▶│  API backend     │
 │ (describe +  │     │                  │
 │  pick tests) │     │  1. Parse input  │
 └──────────────┘     │     → tech tags  │
        ▲             │  2. Rule engine  │──▶ rules/*.yaml
        │             │  3. AI layer     │──▶ Claude / OpenAI / local
        │             │  4. Merge+dedupe │
        │             │  5. Generators   │──▶ templates/
        └─────────────│     plan+scripts │
                      └──────────────────┘
```

1. **Parse input** – free text is converted into normalized tech tags (e.g. `lang:rust`, `framework:actix`, `db:postgres`, `auth:jwt`). Picked tags are used as-is.
2. **Rule engine** – each rule says "if these tags are present, recommend these tests". Deterministic and offline.
3. **AI layer** – sends tags + description + the rule results to the configured AI provider and asks for *additional* tests, returned as structured JSON. AI never removes rule-based tests.
4. **Merge** – duplicates are removed, everything is ranked by severity and effort.
5. **Generators** – each test can have one or more script templates that are filled in with target details (base URL, endpoints, etc.).

---

## Example

**Input:** `Rust API (Actix-web), PostgreSQL via sqlx, JWT auth, React SPA, hosted on Docker`

**Rule-based output (excerpt):**

| Priority | Test | Source | Script |
|---|---|---|---|
| High | JWT: `alg:none`, weak secret, missing expiry check | WSTG-SESS-10 | `jwt_checks.py` |
| High | Dependency audit for Rust crates | ASVS 14.2 | `cargo audit` command |
| High | SQL injection on raw `sqlx::query` strings | WSTG-INPV-05 | Semgrep rule |
| Medium | `unsafe` blocks review | Rust rule | Semgrep / `cargo geiger` |
| Medium | CORS misconfiguration | WSTG-CLNT-07 | `cors_check.py` |
| Medium | Security headers (CSP, HSTS, etc.) | WSTG-CONF-07 | ZAP baseline config |
| Low | Container image vulnerabilities | ASVS 14.1 | Trivy command |

**AI suggestions (excerpt):** "Check for panics on malformed input that could crash Actix workers (denial of service)" – with a suggested fuzzing script.

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

Example `.env`:

```bash
AI_PROVIDER=local            # anthropic | openai | local | none
AI_MODEL=qwen2.5:14b         # model name for the chosen provider

ANTHROPIC_API_KEY=
OPENAI_API_KEY=
LOCAL_BASE_URL=http://localhost:11434/v1   # Ollama's OpenAI-compatible endpoint
```

The provider and model can also be switched per run from a dropdown in the UI, which makes it easy to compare suggestions between models.

Because the AI output must be valid JSON, every response is validated against the `SuggestedTest` schema. If parsing fails, the request is retried once with the error included; if it fails again, the run continues with rule-based results only and shows a warning. Smaller local models fail this more often, so a model of roughly 7B parameters or larger is recommended.

---

## Supported output formats (initial)

| Type | Tool / format |
|---|---|
| Dynamic web scanning | OWASP ZAP Automation Framework (`.yaml`) |
| Static analysis | Semgrep rules (`.yaml`) |
| Dependency audit | `cargo audit`, `npm audit`, `pip-audit` commands |
| Container scan | Trivy commands |
| Custom checks | Python scripts using `httpx` + `pytest` |
| Test plan | Markdown checklist |

---

## Rule format

Rules live in `rules/` as YAML so they're easy to add and version-control.

```yaml
id: jwt-weak-validation
title: JWT validation weaknesses
when:
  all: [auth:jwt]
severity: high
effort: low          # low | medium | high
references:
  - WSTG-SESS-10
  - ASVS-3.5
description: >
  Verify the server rejects tokens with alg "none", tokens signed with a
  different key, expired tokens, and tokens with tampered claims.
expected_secure_behavior: All manipulated tokens return 401.
scripts:
  - template: templates/python/jwt_checks.py.j2
    params: [base_url, protected_endpoint, valid_token]
```

`when` supports `all`, `any` and `none` so rules can be combined, e.g. "Rust **and** raw SQL **but not** an ORM".

---

## Tech stack (proposed)

Since this is a single-user tool, the stack is kept simple:

- **Frontend:** React + Vite + Tailwind
- **Backend:** Rust + Axum (async web framework on Tokio)
- **Serialization:** Serde (JSON for the API, YAML for rules)
- **Storage:** SQLite via `sqlx` (compile-time checked queries)
- **Templates:** `minijinja` (Jinja2 syntax, so templates stay readable)
- **AI:** provider-agnostic layer called with `reqwest`; structured JSON output parsed into Serde structs (see *AI providers* above)
- **Deployment:** single Rust binary that also serves the built frontend, run as a systemd service in an **LXC container** (Docker Compose kept as an optional alternative for development)

The generated *output* scripts are still Python/YAML/shell, since that's what the security tools themselves use. Only the tool's own backend is Rust.

---

## Project structure

```
sectestgen/
├── frontend/              # React UI
├── backend/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs        # Axum entrypoint + routes
│   │   ├── parser.rs      # free text → tags
│   │   ├── rules.rs       # rule engine
│   │   ├── ai/
│   │   │   ├── mod.rs     # AiProvider trait + shared prompt/JSON handling
│   │   │   ├── anthropic.rs
│   │   │   ├── openai.rs
│   │   │   └── local.rs   # OpenAI-compatible endpoints (Ollama, llama.cpp, vLLM...)
│   │   ├── merge.rs       # dedupe + ranking
│   │   ├── db.rs          # SQLite (sqlx)
│   │   └── generators/    # plan + script output
│   ├── migrations/        # sqlx migrations
│   └── tests/
├── rules/                 # YAML rule base
├── templates/             # script templates (.j2)
├── deploy/
│   ├── sectestgen.service # systemd unit
│   └── install.sh         # sets up user, folders and service inside the LXC
├── docker-compose.yml     # optional, for development
└── README.md
```

---

## Getting started (planned)

### Development (on your own machine)

```bash
git clone <repo> && cd sectestgen
cp .env.example .env              # choose AI provider (see AI providers)
cd frontend && npm install && npm run dev      # http://localhost:5173
cd ../backend && cargo run                     # API on http://localhost:8080
```

AI suggestions are optional: with `AI_PROVIDER=none`, the tool runs in rules-only mode.

### Production: LXC container

The app is designed to run natively in an unprivileged LXC container (e.g. on Proxmox) as a single binary. Axum serves both the API and the built frontend, so there is no Node.js or Docker needed inside the container.

**Recommended container resources** (without a local AI model):

| Resource | Value |
|---|---|
| Template | Debian 12 or Ubuntu 24.04 |
| CPU | 1 core |
| RAM | 512 MB |
| Disk | 4 GB |
| Type | Unprivileged, no nesting needed |

**1. Build the release** (on your workstation or a CI runner, not in the small container: compiling Rust needs roughly 2 GB RAM or more):

```bash
cd frontend && npm run build              # → frontend/dist
cd ../backend && cargo build --release    # → target/release/sectestgen
```

**2. Copy to the container and install:**

```bash
scp backend/target/release/sectestgen root@<lxc-ip>:/usr/local/bin/
scp -r frontend/dist rules templates deploy root@<lxc-ip>:/opt/sectestgen/
ssh root@<lxc-ip> 'bash /opt/sectestgen/deploy/install.sh'
```

`install.sh` creates a dedicated `sectestgen` system user, puts config in `/etc/sectestgen/sectestgen.env` (permissions `600`), data in `/var/lib/sectestgen/` (SQLite database) and enables the systemd service.

**3. systemd unit** (`deploy/sectestgen.service`):

```ini
[Unit]
Description=SecTestGen
After=network-online.target

[Service]
User=sectestgen
EnvironmentFile=/etc/sectestgen/sectestgen.env
ExecStart=/usr/local/bin/sectestgen
WorkingDirectory=/opt/sectestgen
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/sectestgen

[Install]
WantedBy=multi-user.target
```

**4. Open** `http://<lxc-ip>:8080` from your browser.

Relevant settings in `sectestgen.env`:

```bash
BIND_ADDR=0.0.0.0:8080            # container has its own IP, so bind to it
DATABASE_URL=sqlite:///var/lib/sectestgen/sectestgen.db
STATIC_DIR=/opt/sectestgen/dist
RULES_DIR=/opt/sectestgen/rules
TEMPLATES_DIR=/opt/sectestgen/templates
AUTH_PASSWORD_HASH=               # see "Security of the tool itself"
```

**Updating:** build a new release, copy the binary over, then `systemctl restart sectestgen`. Rules and templates can be updated the same way without rebuilding.

**Local AI model with LXC:** run Ollama (or another OpenAI-compatible server) in its **own** LXC container or VM rather than in the app container, and point `LOCAL_BASE_URL` at it, e.g. `http://<ollama-lxc-ip>:11434/v1`. That container needs far more resources (a 7–14B model needs roughly 8–16 GB RAM, or a GPU passed through to the container), and keeping it separate lets the app container stay small.

**Backups:** the only state is the SQLite file in `/var/lib/sectestgen/` plus the env file, so a normal LXC snapshot or `vzdump` backup covers everything.

---

## Roadmap

- [ ] **MVP:** tag picker, ~30 rules (web basics, JWT, SQLi, XSS, headers, deps), Markdown plan export
- [ ] Free-text parsing to tags
- [ ] AI suggestions layer with labeled output
- [ ] Script generation (ZAP, Semgrep, Python checks)
- [ ] Project history and re-generation
- [ ] Mobile app rules (MASVS: Android/iOS)
- [ ] Optional: run selected scripts from the UI and collect results
- [ ] LXC deployment: `install.sh`, systemd unit, release build script
- [ ] Optional: import a stack automatically from `Cargo.toml`, `package.json`, `requirements.txt`

---

## Security of the tool itself

- Because an LXC container is reachable on your network, the app has a simple **single-user login** (password hash in `AUTH_PASSWORD_HASH`, session cookie with `HttpOnly`, `Secure` and `SameSite=Strict`).
- Restrict access further with the Proxmox/LXC firewall (allow port 8080 only from your own machine or VPN), and put it behind a reverse proxy with HTTPS (e.g. Caddy) if you access it from outside your LAN.
- Runs as an unprivileged LXC container with a dedicated non-root system user and a hardened systemd unit.
- API keys stored in `.env`, never sent to the frontend.
- Use the local provider when describing sensitive or confidential systems, so nothing about your target leaves your machine.
- Generated scripts are shown for review before download; nothing runs automatically.
- Target URLs are stored per project so scripts can't accidentally point at the wrong host.
