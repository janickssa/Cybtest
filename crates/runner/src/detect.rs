//! Stack detection from manifest files, lockfiles and file extensions.
//! Files are only read, never executed.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use common::Tag;

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
];
const MAX_ENTRIES: usize = 200_000;
const MAX_READ: u64 = 4 * 1024 * 1024;

const RUST_DEPS: &[(&str, &str)] = &[
    ("actix-web", "fw:actix-web"),
    ("axum", "fw:axum"),
    ("sqlx", "lib:sqlx"),
    ("diesel", "db:orm"),
    ("sea-orm", "db:orm"),
    ("jsonwebtoken", "auth:jwt"),
    ("tokio-postgres", "db:postgres"),
    ("postgres", "db:postgres"),
    ("mysql", "db:mysql"),
    ("mysql_async", "db:mysql"),
    ("rusqlite", "db:sqlite"),
    ("mongodb", "db:mongodb"),
    ("async-graphql", "api:graphql"),
    ("juniper", "api:graphql"),
    ("tokio-tungstenite", "feature:websocket"),
    ("tungstenite", "feature:websocket"),
    ("oauth2", "auth:oauth"),
    ("openidconnect", "auth:oauth"),
    ("quick-xml", "feature:xml"),
    ("tower-sessions", "auth:session"),
    ("actix-session", "auth:session"),
    ("argon2", "auth:login"),
    ("bcrypt", "auth:login"),
];
const NPM_DEPS: &[(&str, &str)] = &[
    ("react", "fw:react"),
    ("next", "fw:nextjs"),
    ("express", "fw:express"),
    ("jsonwebtoken", "auth:jwt"),
    ("jose", "auth:jwt"),
    ("pg", "db:postgres"),
    ("mysql", "db:mysql"),
    ("mysql2", "db:mysql"),
    ("sqlite3", "db:sqlite"),
    ("better-sqlite3", "db:sqlite"),
    ("mongoose", "db:mongodb"),
    ("mongodb", "db:mongodb"),
    ("prisma", "db:orm"),
    ("@prisma/client", "db:orm"),
    ("sequelize", "db:orm"),
    ("typeorm", "db:orm"),
    ("drizzle-orm", "db:orm"),
    ("multer", "feature:file-upload"),
    ("graphql", "api:graphql"),
    ("@apollo/server", "api:graphql"),
    ("ws", "feature:websocket"),
    ("socket.io", "feature:websocket"),
    ("stripe", "feature:payments"),
    ("typescript", "lang:typescript"),
    ("passport", "auth:login"),
    ("next-auth", "auth:login"),
    ("express-session", "auth:session"),
    ("xml2js", "feature:xml"),
];
const PY_DEPS: &[(&str, &str)] = &[
    ("django", "fw:django"),
    ("flask", "fw:flask"),
    ("fastapi", "fw:fastapi"),
    ("sqlalchemy", "db:orm"),
    ("pyjwt", "auth:jwt"),
    ("python-jose", "auth:jwt"),
    ("psycopg2", "db:postgres"),
    ("psycopg2-binary", "db:postgres"),
    ("psycopg", "db:postgres"),
    ("asyncpg", "db:postgres"),
    ("pymysql", "db:mysql"),
    ("mysqlclient", "db:mysql"),
    ("pymongo", "db:mongodb"),
    ("lxml", "feature:xml"),
    ("stripe", "feature:payments"),
    ("graphene", "api:graphql"),
    ("strawberry-graphql", "api:graphql"),
    ("authlib", "auth:oauth"),
];
const PHP_DEPS: &[(&str, &str)] = &[
    ("laravel/framework", "fw:laravel"),
    ("firebase/php-jwt", "auth:jwt"),
    ("lcobucci/jwt", "auth:jwt"),
    ("doctrine/orm", "db:orm"),
];
const EXTENSIONS: &[(&str, &str)] = &[
    ("rs", "lang:rust"),
    ("py", "lang:python"),
    ("js", "lang:javascript"),
    ("jsx", "lang:javascript"),
    ("mjs", "lang:javascript"),
    ("ts", "lang:typescript"),
    ("tsx", "lang:typescript"),
    ("php", "lang:php"),
    ("java", "lang:java"),
    ("kt", "lang:java"),
    ("go", "lang:go"),
    ("cs", "lang:csharp"),
];

#[derive(Default)]
struct Found(BTreeMap<String, String>);

impl Found {
    fn add(&mut self, tag: &str, evidence: impl FnOnce() -> String) {
        self.0.entry(tag.to_string()).or_insert_with(evidence);
    }

    fn deps<'a>(
        &mut self,
        table: &[(&str, &str)],
        names: impl IntoIterator<Item = &'a str>,
        file: &str,
    ) {
        for name in names {
            if let Some((dep, tag)) = table.iter().find(|(d, _)| *d == name) {
                self.add(tag, || format!("{dep} found in {file}"));
            }
        }
    }
}

fn read(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    (meta.len() <= MAX_READ)
        .then(|| fs::read_to_string(path).ok())
        .flatten()
}

/// Dependency names from Cargo.lock (`name = "x"`) or Cargo.toml dependency tables.
fn cargo_deps(text: &str, lock: bool) -> Vec<String> {
    let mut in_deps = false;
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_deps = line.contains("dependencies");
            continue;
        }
        if lock {
            if let Some(name) = line.strip_prefix("name = \"") {
                out.push(name.trim_end_matches('"').to_string());
            }
        } else if in_deps {
            if let Some(key) = line.split(['=', '.']).next() {
                out.push(key.trim().trim_matches('"').to_string());
            }
        }
    }
    out
}

fn json_keys(text: &str, fields: &[&str]) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    fields
        .iter()
        .filter_map(|f| value.get(f)?.as_object())
        .flat_map(|o| o.keys().cloned())
        .collect()
}

fn requirement_names(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('-'))
        .filter_map(|l| l.split(['=', '<', '>', '!', '~', ';', '[', ' ']).next())
        .map(|n| n.to_lowercase().replace('_', "-"))
        .collect()
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    let is_word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_');
    haystack.match_indices(needle).any(|(i, _)| {
        !is_word(haystack[..i].chars().next_back())
            && !is_word(haystack[i + needle.len()..].chars().next())
    })
}

/// Detects the stack of the project unpacked at `root`.
pub fn detect(root: &Path) -> Vec<Tag> {
    let mut found = Found::default();
    found.add("input:source", || "Project upload".into());
    let mut ext_counts: BTreeMap<&str, (usize, &str)> = BTreeMap::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut seen = 0;

    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > MAX_ENTRIES {
                break;
            }
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().to_string();
            if kind.is_dir() {
                if name.ends_with(".xcodeproj") || name.ends_with(".xcworkspace") {
                    let rel = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .to_string();
                    found.add("mobile:ios", || format!("Xcode project {rel}"));
                }
                if !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push(path);
                }
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            inspect_file(&mut found, &path, &name, &rel);
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if let Some((e, tag)) = EXTENSIONS.iter().find(|(e, _)| *e == ext) {
                    ext_counts.entry(tag).or_insert((0, e)).0 += 1;
                }
            }
        }
    }
    for (tag, (count, ext)) in ext_counts {
        found.add(tag, || {
            format!("{count} .{ext} file{}", if count == 1 { "" } else { "s" })
        });
    }
    found
        .0
        .into_iter()
        .map(|(id, evidence)| Tag { id, evidence })
        .collect()
}

fn inspect_file(found: &mut Found, path: &Path, name: &str, rel: &str) {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "cargo.lock" | "cargo.toml" => {
            found.add("lang:rust", || format!("{rel} found"));
            if let Some(text) = read(path) {
                let deps = cargo_deps(&text, lower == "cargo.lock");
                found.deps(RUST_DEPS, deps.iter().map(String::as_str), rel);
            }
        }
        "package.json" => {
            found.add("runtime:node", || format!("{rel} found"));
            if let Some(text) = read(path) {
                let deps = json_keys(&text, &["dependencies", "devDependencies"]);
                found.deps(NPM_DEPS, deps.iter().map(String::as_str), rel);
            }
        }
        "pyproject.toml" | "pipfile" | "poetry.lock" | "uv.lock" | "setup.py" => {
            found.add("lang:python", || format!("{rel} found"));
            if let Some(text) = read(path).map(|t| t.to_lowercase()) {
                let names = PY_DEPS
                    .iter()
                    .map(|(d, _)| *d)
                    .filter(|d| contains_word(&text, d));
                found.deps(PY_DEPS, names, rel);
            }
        }
        "composer.json" => {
            found.add("lang:php", || format!("{rel} found"));
            if let Some(text) = read(path) {
                let deps = json_keys(&text, &["require", "require-dev"]);
                found.deps(PHP_DEPS, deps.iter().map(String::as_str), rel);
            }
        }
        "pom.xml" | "build.gradle" | "build.gradle.kts" => {
            found.add("lang:java", || format!("{rel} found"));
            if let Some(text) = read(path) {
                if text.contains("spring-boot") {
                    found.add("fw:spring", || format!("spring-boot found in {rel}"));
                }
                if text.contains("com.android.application") || text.contains("com.android.library")
                {
                    found.add("mobile:android", || {
                        format!("Android Gradle plugin in {rel}")
                    });
                }
                if text.contains("jjwt") {
                    found.add("auth:jwt", || format!("jjwt found in {rel}"));
                }
            }
        }
        "go.mod" => found.add("lang:go", || format!("{rel} found")),
        "androidmanifest.xml" => found.add("mobile:android", || format!("{rel} found")),
        "info.plist" => found.add("mobile:ios", || format!("{rel} found")),
        "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml" => {
            found.add("infra:docker", || format!("{rel} found"))
        }
        ".gitlab-ci.yml" => found.add("ci:gitlab", || format!("{rel} found")),
        "nginx.conf" => found.add("server:nginx", || format!("{rel} found")),
        ".htaccess" | "httpd.conf" | "apache2.conf" => {
            found.add("server:apache", || format!("{rel} found"))
        }
        "wp-config.php" | "wp-config-sample.php" => {
            found.add("fw:wordpress", || format!("{rel} found"))
        }
        _ => {}
    }
    if lower.starts_with("requirements") && lower.ends_with(".txt") {
        found.add("lang:python", || format!("{rel} found"));
        if let Some(text) = read(path) {
            let names = requirement_names(&text);
            found.deps(PY_DEPS, names.iter().map(String::as_str), rel);
        }
    }
    if lower == "dockerfile" || lower.starts_with("dockerfile.") || lower.ends_with(".dockerfile") {
        found.add("infra:docker", || format!("{rel} found"));
    }
    if lower.ends_with(".tf") {
        found.add("infra:terraform", || format!("{rel} found"));
    }
    if lower.ends_with(".csproj") {
        found.add("lang:csharp", || format!("{rel} found"));
    }
    let is_yaml = lower.ends_with(".yml") || lower.ends_with(".yaml");
    if is_yaml && rel.contains(".github/workflows/") {
        found.add("ci:github-actions", || format!("{rel} found"));
    } else if is_yaml && lower == "chart.yaml" {
        found.add("infra:kubernetes", || format!("Helm chart {rel}"));
    } else if is_yaml {
        if let Some(text) = read(path) {
            if text.contains("apiVersion:") && text.contains("\nkind:") {
                found.add("infra:kubernetes", || format!("Kubernetes manifest {rel}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_stack_with_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("backend/src")).unwrap();
        fs::create_dir_all(root.join("web/node_modules/express")).unwrap();
        fs::create_dir_all(root.join(".github/workflows")).unwrap();
        fs::write(
            root.join("backend/Cargo.toml"),
            "[package]\nname = \"x\"\n\n[dependencies]\naxum = \"0.8\"\nsqlx = { version = \"0.8\" }\njsonwebtoken.workspace = true\n",
        )
        .unwrap();
        fs::write(root.join("backend/src/main.rs"), "fn main() {}").unwrap();
        fs::write(
            root.join("web/package.json"),
            r#"{"dependencies":{"react":"19"},"devDependencies":{"typescript":"5"}}"#,
        )
        .unwrap();
        fs::write(
            root.join("web/node_modules/express/package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        fs::write(
            root.join("requirements.txt"),
            "Django==4.2\nPyJWT>=2\n# flask\n",
        )
        .unwrap();
        fs::write(root.join("Dockerfile"), "FROM debian:12").unwrap();
        fs::write(root.join(".github/workflows/ci.yml"), "on: push").unwrap();

        let tags = detect(root);
        let get = |id: &str| {
            tags.iter()
                .find(|t| t.id == id)
                .map(|t| t.evidence.as_str())
        };
        assert_eq!(get("fw:axum"), Some("axum found in backend/Cargo.toml"));
        assert_eq!(get("lib:sqlx"), Some("sqlx found in backend/Cargo.toml"));
        assert!(get("auth:jwt").is_some_and(|e| e.contains("jsonwebtoken") || e.contains("pyjwt")));
        assert_eq!(get("fw:react"), Some("react found in web/package.json"));
        assert!(get("lang:typescript").is_some());
        assert_eq!(get("fw:django"), Some("django found in requirements.txt"));
        assert!(
            get("fw:flask").is_none(),
            "commented-out requirement matched"
        );
        assert!(
            get("fw:express").is_none(),
            "node_modules should be skipped"
        );
        assert_eq!(get("infra:docker"), Some("Dockerfile found"));
        assert_eq!(
            get("ci:github-actions"),
            Some(".github/workflows/ci.yml found")
        );
        assert_eq!(get("input:source"), Some("Project upload"));
    }
}
