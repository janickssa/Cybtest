//! Built-in passive checks against a URL: stack fingerprinting and CORS.
//! Each sends only a few ordinary requests.

use std::collections::BTreeMap;
use std::time::Duration;

use common::{Finding, Scope, Severity, Tag};
use reqwest::header::{HeaderMap, HeaderValue};

const MAX_BODY: usize = 512 * 1024;
const USER_AGENT: &str = "SecTestGen/0.1 (+passive check)";

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        // Internal test sites often use self-signed certificates; TLS quality is testssl's job.
        .danger_accept_invalid_certs(true)
        .build()
        .expect("http client")
}

async fn read_body(mut res: reqwest::Response) -> String {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = res.chunk().await {
        body.extend_from_slice(&chunk);
        if body.len() >= MAX_BODY {
            break;
        }
    }
    String::from_utf8_lossy(&body).to_string()
}

/// Fetches the page (following up to 3 in-scope redirects) and derives tags
/// from headers, cookies and markup.
pub async fn fingerprint(scope: &Scope, url: &url::Url) -> Result<Vec<Tag>, String> {
    let client = client();
    let mut current = url.clone();
    let mut res = None;
    for _ in 0..4 {
        scope.check_url(&current).await?;
        let r = client
            .get(current.clone())
            .send()
            .await
            .map_err(|e| format!("Request failed: {e}"))?;
        let next = r
            .status()
            .is_redirection()
            .then(|| {
                r.headers()
                    .get("location")?
                    .to_str()
                    .ok()
                    .and_then(|l| current.join(l).ok())
            })
            .flatten();
        match next {
            Some(next) => current = next,
            None => {
                res = Some(r);
                break;
            }
        }
    }
    let res = res.ok_or("Too many redirects")?;
    let host = current.host_str().unwrap_or("the site").to_string();
    let headers = res.headers().clone();
    let body = read_body(res).await.to_lowercase();

    let mut found: BTreeMap<String, String> = BTreeMap::new();
    let mut add = |tag: &str, evidence: String| {
        found.entry(tag.to_string()).or_insert(evidence);
    };
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };

    if let Some(server) = header("server") {
        let s = server.to_lowercase();
        let ev = || format!("Server: {server} header from {host}");
        if s.contains("nginx") {
            add("server:nginx", ev());
        } else if s.contains("apache") {
            add("server:apache", ev());
        } else if s.contains("microsoft-iis") {
            add("lang:csharp", ev());
        }
    }
    if let Some(powered) = header("x-powered-by") {
        let p = powered.to_lowercase();
        let ev = || format!("X-Powered-By: {powered} header from {host}");
        for (needle, tag) in [
            ("php", "lang:php"),
            ("express", "fw:express"),
            ("asp.net", "lang:csharp"),
            ("next.js", "fw:nextjs"),
        ] {
            if p.contains(needle) {
                add(tag, ev());
            }
        }
    }
    for cookie in headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        let name = cookie.split('=').next().unwrap_or("").trim().to_string();
        let ev = || format!("{name} cookie set by {host}");
        add("auth:session", ev());
        match name.to_lowercase().as_str() {
            "phpsessid" => add("lang:php", ev()),
            "jsessionid" => add("lang:java", ev()),
            "laravel_session" | "xsrf-token" => add("fw:laravel", ev()),
            "csrftoken" | "sessionid" => add("fw:django", ev()),
            "connect.sid" => add("fw:express", ev()),
            _ => {}
        }
    }
    let in_body = |needle: &str| body.contains(needle);
    if in_body("wp-content/") || in_body("wp-includes/") {
        add(
            "fw:wordpress",
            format!("wp-content paths in the page from {host}"),
        );
    }
    if in_body("__next_data__") || in_body("/_next/") {
        add(
            "fw:nextjs",
            format!("Next.js assets in the page from {host}"),
        );
    }
    if in_body("csrfmiddlewaretoken") {
        add(
            "fw:django",
            format!("Django CSRF field in the page from {host}"),
        );
    }
    if in_body("type=\"password\"") || in_body("type='password'") || in_body("type=password") {
        add("auth:login", format!("Password field on {current}"));
    }
    if header("content-type").is_some_and(|c| c.contains("json")) {
        add("api:rest", format!("JSON response from {current}"));
    }
    Ok(found
        .into_iter()
        .map(|(id, evidence)| Tag { id, evidence })
        .collect())
}

/// Checks whether the site reflects untrusted origins in its CORS headers.
pub async fn cors(url: &url::Url, log: impl Fn(String)) -> Result<Vec<Finding>, String> {
    let client = client();
    let mut findings = Vec::new();
    for origin in ["https://sectestgen-cors-check.example", "null"] {
        let mut headers = HeaderMap::new();
        headers.insert("origin", HeaderValue::from_static(origin));
        let res = client
            .get(url.clone())
            .headers(headers)
            .send()
            .await
            .map_err(|e| format!("Request failed: {e}"))?;
        let get = |name: &str| {
            res.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        let (allow_origin, credentials) = (
            get("access-control-allow-origin"),
            get("access-control-allow-credentials"),
        );
        log(format!(
            "Origin: {origin} → {} Access-Control-Allow-Origin: {allow_origin:?}, Allow-Credentials: {credentials:?}",
            res.status()
        ));
        if allow_origin != origin {
            continue;
        }
        let with_credentials = credentials.eq_ignore_ascii_case("true");
        findings.push(Finding {
            tool: "built-in".into(),
            rule_id: if origin == "null" { "cors-null-origin" } else { "cors-reflected-origin" }.into(),
            title: match (origin, with_credentials) {
                ("null", true) => "CORS allows the null origin with credentials".into(),
                ("null", false) => "CORS allows the null origin".into(),
                (_, true) => "CORS reflects any origin with credentials".into(),
                (_, false) => "CORS reflects any origin".into(),
            },
            severity: if with_credentials { Severity::High } else { Severity::Medium },
            location: Some(url.to_string()),
            message: format!(
                "A request with Origin: {origin} was answered with Access-Control-Allow-Origin: {allow_origin}{}. {}",
                if with_credentials { " and Access-Control-Allow-Credentials: true" } else { "" },
                if with_credentials {
                    "Any website a logged-in user visits can read their data from this site."
                } else {
                    "Any website can read public responses from this site."
                }
            ),
            snippet: None,
            help: Some("Only send Access-Control-Allow-Origin for an explicit list of trusted origins, and never for \"null\".".into()),
            help_url: Some("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing".into()),
        });
    }
    Ok(findings)
}
