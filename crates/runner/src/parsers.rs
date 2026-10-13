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
    let value: Value = serde_json::from_str(data).map_err(|e| format!("invalid JSON: {e}"))?;
    match parser {
        "sarif" => sarif(&value, ctx),
        "cargo-audit" => cargo_audit(&value, ctx),
        other => Err(format!("unknown parser {other}")),
    }
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
