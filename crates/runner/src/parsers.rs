//! Turns tool output (SARIF, cargo-audit JSON) into normalized findings.

use common::{Finding, Severity};
use serde_json::Value;

const MAX_TEXT: usize = 2000;

pub struct Context<'a> {
    pub tool: &'a str,
    /// Absolute path of the unpacked project, stripped from paths and messages.
    pub src: &'a str,
    pub severity: Option<Severity>,
    /// Location for findings whose output has none (e.g. the Cargo.lock path).
    pub default_location: Option<String>,
}

impl Context<'_> {
    fn clean(&self, text: &str) -> String {
        let text = text
            .replace(&format!("file://{}/", self.src), "")
            .replace(&format!("{}/", self.src), "")
            .replace(self.src, ".");
        truncate(text.trim(), MAX_TEXT)
    }
}

fn truncate(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &text[..i]),
        None => text.to_string(),
    }
}

pub fn parse(parser: &str, data: &str, ctx: &Context) -> Result<Vec<Finding>, String> {
    if parser == "nuclei-jsonl" {
        return nuclei(data, ctx);
    }
    let value: Value = serde_json::from_str(data).map_err(|e| format!("invalid JSON: {e}"))?;
    match parser {
        "sarif" => sarif(&value, ctx),
        "cargo-audit" => cargo_audit(&value, ctx),
        "zap-json" => zap(&value, ctx),
        "testssl-json" => testssl(&value, ctx),
        other => Err(format!("unknown parser {other}")),
    }
}

/// ZAP's HTML snippets (`<p>…</p>`) as plain text.
fn strip_html(html: &str) -> String {
    let text = html.replace("</p><p>", "\n").replace("<br>", "\n");
    let mut out = String::with_capacity(text.len());
    let mut in_tag = false;
    for c in text.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&amp;", "&")
}

fn zap(doc: &Value, ctx: &Context) -> Result<Vec<Finding>, String> {
    let sites = doc
        .get("site")
        .and_then(Value::as_array)
        .ok_or("ZAP report without sites")?;
    let mut findings = Vec::new();
    for alert in sites
        .iter()
        .filter_map(|s| s.get("alerts")?.as_array())
        .flatten()
    {
        let instances = alert
            .get("instances")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let first = instances.first().cloned().unwrap_or(Value::Null);
        let count: usize = text(alert, &["count"])
            .and_then(|c| c.parse().ok())
            .unwrap_or(instances.len());
        let location = text(&first, &["uri"]).map(|uri| {
            let param = text(&first, &["param"])
                .map(|p| format!(" (parameter {p})"))
                .unwrap_or_default();
            let more = if count > 1 {
                format!(" and {} more", count - 1)
            } else {
                String::new()
            };
            format!("{uri}{param}{more}")
        });
        let reference = text(alert, &["reference"]).map(strip_html);
        findings.push(Finding {
            tool: ctx.tool.to_string(),
            rule_id: text(alert, &["alertRef"])
                .or_else(|| text(alert, &["pluginid"]))
                .unwrap_or("zap")
                .to_string(),
            title: text(alert, &["name"])
                .or_else(|| text(alert, &["alert"]))
                .unwrap_or("ZAP alert")
                .to_string(),
            severity: ctx.severity.unwrap_or(match text(alert, &["riskcode"]) {
                Some("3") => Severity::High,
                Some("2") => Severity::Medium,
                Some("1") => Severity::Low,
                _ => Severity::Info,
            }),
            location: location.or_else(|| ctx.default_location.clone()),
            message: truncate(
                strip_html(text(alert, &["desc"]).unwrap_or("")).trim(),
                MAX_TEXT,
            ),
            snippet: text(&first, &["evidence"]).map(|e| truncate(e, 500)),
            help: text(alert, &["solution"]).map(|h| truncate(strip_html(h).trim(), MAX_TEXT)),
            help_url: reference.and_then(|r| {
                r.split_whitespace()
                    .find(|w| w.starts_with("http"))
                    .map(str::to_string)
            }),
        });
    }
    Ok(findings)
}

fn nuclei(data: &str, ctx: &Context) -> Result<Vec<Finding>, String> {
    let mut findings = Vec::new();
    for line in data.lines().filter(|l| !l.trim().is_empty()) {
        let v: Value =
            serde_json::from_str(line).map_err(|e| format!("invalid nuclei JSON line: {e}"))?;
        let info = &v["info"];
        let extracted: Vec<&str> = v["extracted-results"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        findings.push(Finding {
            tool: ctx.tool.to_string(),
            rule_id: text(&v, &["template-id"]).unwrap_or("nuclei").to_string(),
            title: text(info, &["name"]).unwrap_or("nuclei match").to_string(),
            severity: ctx.severity.unwrap_or(match text(info, &["severity"]) {
                Some("critical" | "high") => Severity::High,
                Some("medium") => Severity::Medium,
                Some("low") => Severity::Low,
                _ => Severity::Info,
            }),
            location: text(&v, &["matched-at"])
                .map(str::to_string)
                .or_else(|| ctx.default_location.clone()),
            message: truncate(text(info, &["description"]).unwrap_or("").trim(), MAX_TEXT),
            snippet: (!extracted.is_empty()).then(|| truncate(&extracted.join("\n"), 500)),
            help: text(info, &["remediation"]).map(|r| truncate(r.trim(), MAX_TEXT)),
            help_url: info["reference"]
                .as_array()
                .and_then(|r| r.first())
                .and_then(Value::as_str)
                .map(str::to_string),
        });
    }
    Ok(findings)
}

fn testssl(doc: &Value, ctx: &Context) -> Result<Vec<Finding>, String> {
    let items = doc.as_array().ok_or("testssl output is not a list")?;
    let mut findings = Vec::new();
    for item in items {
        let severity = match text(item, &["severity"]) {
            Some("CRITICAL" | "HIGH") => Severity::High,
            Some("MEDIUM") => Severity::Medium,
            Some("LOW") => Severity::Low,
            _ => continue,
        };
        let id = text(item, &["id"]).unwrap_or("testssl");
        let finding = text(item, &["finding"]).unwrap_or("");
        let cve = text(item, &["cve"]);
        findings.push(Finding {
            tool: ctx.tool.to_string(),
            rule_id: id.to_string(),
            title: format!("{}: {}", humanize(id), truncate(finding, 120)),
            severity: ctx.severity.unwrap_or(severity),
            location: ctx.default_location.clone(),
            message: [
                Some(finding.to_string()),
                cve.map(|c| format!("CVE: {c}")),
                text(item, &["cwe"]).map(|c| format!("CWE: {c}")),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n"),
            snippet: None,
            help: None,
            help_url: cve
                .and_then(|c| c.split_whitespace().next())
                .map(|c| format!("https://nvd.nist.gov/vuln/detail/{c}")),
        });
    }
    Ok(findings)
}

fn text<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(v, |v, key| v.get(key))?
        .as_str()
        .filter(|s| !s.trim().is_empty())
}

fn severity_from_score(score: &Value) -> Option<Severity> {
    let score = score.as_f64().or_else(|| score.as_str()?.parse().ok())?;
    Some(if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else if score > 0.0 {
        Severity::Low
    } else {
        Severity::Info
    })
}

fn severity_from_level(level: &str) -> Severity {
    match level {
        "error" => Severity::High,
        "note" => Severity::Low,
        "none" => Severity::Info,
        _ => Severity::Medium,
    }
}

/// `python.lang.security.audit.formatted-sql-query` → "Formatted sql query".
fn humanize(rule_id: &str) -> String {
    let last = rule_id
        .rsplit('.')
        .next()
        .unwrap_or(rule_id)
        .replace(['-', '_'], " ");
    let mut chars = last.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

fn sarif(doc: &Value, ctx: &Context) -> Result<Vec<Finding>, String> {
    let runs = doc
        .get("runs")
        .and_then(Value::as_array)
        .ok_or("SARIF without runs")?;
    let mut findings = Vec::new();
    for run in runs {
        let rules = run
            .pointer("/tool/driver/rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let empty = Vec::new();
        for result in run
            .get("results")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
        {
            let rule_id = text(result, &["ruleId"]).unwrap_or("unknown").to_string();
            let rule = result
                .get("ruleIndex")
                .or_else(|| result.pointer("/rule/index"))
                .and_then(Value::as_u64)
                .and_then(|i| rules.get(i as usize))
                .or_else(|| rules.iter().find(|r| text(r, &["id"]) == Some(&rule_id)))
                .cloned()
                .unwrap_or(Value::Null);

            let severity = ctx.severity.unwrap_or_else(|| {
                rule.pointer("/properties/security-severity")
                    .or_else(|| result.pointer("/properties/security-severity"))
                    .and_then(severity_from_score)
                    .unwrap_or_else(|| {
                        severity_from_level(
                            text(result, &["level"])
                                .or_else(|| text(&rule, &["defaultConfiguration", "level"]))
                                .unwrap_or("warning"),
                        )
                    })
            });

            let message = text(result, &["message", "text"])
                .map(|m| ctx.clean(m))
                .unwrap_or_default();
            let title = text(&rule, &["shortDescription", "text"])
                .filter(|t| !t.starts_with("Semgrep Finding") && *t != rule_id)
                .map(|t| ctx.clean(t))
                .unwrap_or_else(|| humanize(&rule_id));
            // fullDescription is usually the concise advice; help.text often repeats the message.
            let help = text(&rule, &["fullDescription", "text"])
                .or_else(|| text(&rule, &["help", "text"]))
                .map(|h| ctx.clean(h))
                .filter(|h| *h != message && *h != title);

            let loc = result.pointer("/locations/0/physicalLocation");
            let location = loc
                .and_then(|l| text(l, &["artifactLocation", "uri"]))
                .map(|uri| {
                    let uri = ctx.clean(uri);
                    match loc
                        .and_then(|l| l.pointer("/region/startLine"))
                        .and_then(Value::as_u64)
                    {
                        Some(line) => format!("{uri}:{line}"),
                        None => uri,
                    }
                })
                .or_else(|| ctx.default_location.clone());
            let snippet = loc
                .and_then(|l| text(l, &["region", "snippet", "text"]))
                .map(|s| truncate(s.trim(), 500));

            findings.push(Finding {
                tool: ctx.tool.to_string(),
                rule_id,
                title,
                severity,
                location,
                message,
                snippet,
                help,
                help_url: text(&rule, &["helpUri"]).map(str::to_string),
            });
        }
    }
    Ok(findings)
}

fn cargo_audit(doc: &Value, ctx: &Context) -> Result<Vec<Finding>, String> {
    let list = doc
        .pointer("/vulnerabilities/list")
        .and_then(Value::as_array)
        .ok_or("cargo-audit output without vulnerabilities")?;
    let package = |v: &Value| {
        format!(
            "{} {}",
            text(v, &["package", "name"]).unwrap_or("?"),
            text(v, &["package", "version"]).unwrap_or("?")
        )
    };
    let advisory_url = |adv: &Value, id: &str| {
        text(adv, &["url"])
            .map(str::to_string)
            .unwrap_or_else(|| format!("https://rustsec.org/advisories/{id}"))
    };
    let mut findings = Vec::new();
    for vuln in list {
        let adv = &vuln["advisory"];
        let id = text(adv, &["id"]).unwrap_or("RUSTSEC-unknown").to_string();
        let patched: Vec<&str> = vuln
            .pointer("/versions/patched")
            .and_then(Value::as_array)
            .map(|p| p.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let name = text(vuln, &["package", "name"]).unwrap_or("the crate");
        findings.push(Finding {
            tool: ctx.tool.to_string(),
            title: format!(
                "{} in {}",
                text(adv, &["title"]).unwrap_or(&id),
                package(vuln)
            ),
            severity: ctx.severity.unwrap_or(Severity::High),
            location: ctx.default_location.clone(),
            message: truncate(text(adv, &["description"]).unwrap_or("").trim(), MAX_TEXT),
            snippet: None,
            help: Some(if patched.is_empty() {
                format!("No fixed version of {name} exists. Consider replacing it.")
            } else {
                format!("Upgrade {name} to {}.", patched.join(" or "))
            }),
            help_url: Some(advisory_url(adv, &id)),
            rule_id: id,
        });
    }
    if let Some(warnings) = doc.get("warnings").and_then(Value::as_object) {
        for (kind, items) in warnings {
            for w in items.as_array().into_iter().flatten() {
                let adv = &w["advisory"];
                let id = text(adv, &["id"])
                    .map_or_else(|| format!("{kind}-{}", package(w)), str::to_string);
                findings.push(Finding {
                    tool: ctx.tool.to_string(),
                    title: match text(adv, &["title"]) {
                        Some(t) => format!("{t} in {} ({kind})", package(w)),
                        None => format!("{} is {kind}", package(w)),
                    },
                    severity: Severity::Low,
                    location: ctx.default_location.clone(),
                    message: truncate(text(adv, &["description"]).unwrap_or("").trim(), MAX_TEXT),
                    snippet: None,
                    help: Some(format!(
                        "Update or replace {}.",
                        text(w, &["package", "name"]).unwrap_or("the crate")
                    )),
                    help_url: text(adv, &["id"]).map(|_| advisory_url(adv, &id)),
                    rule_id: id,
                });
            }
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(severity: Option<Severity>) -> Context<'static> {
        Context {
            tool: "t",
            src: "/ws/src",
            severity,
            default_location: Some("Cargo.lock".into()),
        }
    }

    #[test]
    fn parses_sarif_with_security_severity_and_paths() {
        let doc = r#"{"runs":[{"tool":{"driver":{"name":"Trivy","rules":[
            {"id":"DS-0002","shortDescription":{"text":"Image user should not be 'root'"},
             "fullDescription":{"text":"Add a USER instruction."},
             "help":{"text":"Misconfiguration DS-0002 Type: Dockerfile ..."},"helpUri":"https://avd.example/ds002",
             "properties":{"security-severity":"8.0"},"defaultConfiguration":{"level":"error"}}]}},
          "results":[{"ruleId":"DS-0002","ruleIndex":0,"level":"error",
            "message":{"text":"Specify at least 1 USER command in /ws/src/Dockerfile"},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"/ws/src/Dockerfile"},"region":{"startLine":1}}}]}]}]}"#;
        let f = &parse("sarif", doc, &ctx(None)).unwrap()[0];
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.title, "Image user should not be 'root'");
        assert_eq!(f.location.as_deref(), Some("Dockerfile:1"));
        assert_eq!(f.message, "Specify at least 1 USER command in Dockerfile");
        assert_eq!(f.help.as_deref(), Some("Add a USER instruction."));
    }

    #[test]
    fn sarif_without_levels_uses_override_and_humanized_titles() {
        let doc = r#"{"runs":[{"tool":{"driver":{"name":"gitleaks","rules":[]}},
          "results":[{"ruleId":"github-pat","message":{"text":"secret"},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///ws/src/a.py"},"region":{"startLine":2,"snippet":{"text":"REDACTED"}}}}]}]}]}"#;
        let f = &parse("sarif", doc, &ctx(Some(Severity::High))).unwrap()[0];
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.title, "Github pat");
        assert_eq!(f.location.as_deref(), Some("a.py:2"));
        assert_eq!(f.snippet.as_deref(), Some("REDACTED"));
        let f = &parse("sarif", doc, &ctx(None)).unwrap()[0];
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn parses_zap_nuclei_and_testssl() {
        let zap_doc = r#"{"site":[{"@name":"http://t","alerts":[{"pluginid":"10038","alertRef":"10038-1",
            "name":"Content Security Policy (CSP) Header Not Set","riskcode":"2","count":"7",
            "desc":"<p>CSP is an added layer.</p>","solution":"<p>Set the header.</p>",
            "reference":"<p>https://developer.mozilla.org/csp</p><p>https://owasp.org/x</p>",
            "instances":[{"uri":"http://t/","method":"GET","param":"","evidence":""}]}]}]}"#;
        let f = &parse("zap-json", zap_doc, &ctx(None)).unwrap()[0];
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(f.location.as_deref(), Some("http://t/ and 6 more"));
        assert_eq!(f.message, "CSP is an added layer.");
        assert_eq!(f.help.as_deref(), Some("Set the header."));
        assert_eq!(
            f.help_url.as_deref(),
            Some("https://developer.mozilla.org/csp")
        );
        assert_eq!(f.snippet, None);

        let jsonl = "{\"template-id\":\"php-powered-by\",\"info\":{\"name\":\"PHP version disclosed\",\"severity\":\"low\",\"remediation\":\"Remove it.\",\"reference\":[\"https://e.org\"]},\"matched-at\":\"http://t/\",\"extracted-results\":[\"PHP/8.1\"]}\n";
        let f = &parse("nuclei-jsonl", jsonl, &ctx(None)).unwrap()[0];
        assert_eq!(
            (f.severity, f.title.as_str(), f.snippet.as_deref()),
            (Severity::Low, "PHP version disclosed", Some("PHP/8.1"))
        );

        let ssl = r#"[{"id":"cert_chain_of_trust","severity":"CRITICAL","finding":"failed (self signed)."},
            {"id":"TLS1_3","severity":"OK","finding":"offered"},
            {"id":"BREACH","severity":"MEDIUM","finding":"potentially VULNERABLE","cve":"CVE-2013-3587","cwe":"CWE-310"}]"#;
        let f = parse("testssl-json", ssl, &ctx(None)).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].title, "Cert chain of trust: failed (self signed).");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(
            f[1].help_url.as_deref(),
            Some("https://nvd.nist.gov/vuln/detail/CVE-2013-3587")
        );
    }

    #[test]
    fn parses_cargo_audit_json() {
        let doc = r#"{"vulnerabilities":{"count":1,"list":[{"advisory":{"id":"RUSTSEC-2019-0009",
            "title":"Double-free and use-after-free in SmallVec::grow()","description":"Bad things.",
            "url":null},"versions":{"patched":[">=0.6.10"]},"package":{"name":"smallvec","version":"0.6.9"}}]},
          "warnings":{"yanked":[{"kind":"yanked","package":{"name":"smallvec","version":"0.6.9"},"advisory":null}]}}"#;
        let f = parse("cargo-audit", doc, &ctx(None)).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(
            f[0].title,
            "Double-free and use-after-free in SmallVec::grow() in smallvec 0.6.9"
        );
        assert_eq!(f[0].help.as_deref(), Some("Upgrade smallvec to >=0.6.10."));
        assert_eq!(
            f[0].help_url.as_deref(),
            Some("https://rustsec.org/advisories/RUSTSEC-2019-0009")
        );
        assert_eq!(f[1].title, "smallvec 0.6.9 is yanked");
        assert_eq!(f[1].severity, Severity::Low);
    }
}
