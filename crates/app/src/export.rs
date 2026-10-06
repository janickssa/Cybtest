//! Markdown export of an approved test plan.

use std::fmt::Write;

use crate::plan::PlanItem;
use crate::rules::Severity;

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::High => "🔴 High",
        Severity::Medium => "🟠 Medium",
        Severity::Low => "🟡 Low",
        Severity::Info => "⚪ Info",
    }
}

/// Keeps user text from breaking out of a table cell or heading.
fn inline(text: &str) -> String {
    text.replace(['\n', '\r'], " ").replace('|', "\\|")
}

pub fn markdown(
    project: &str,
    url: Option<&str>,
    description: &str,
    tags: &[String],
    items: &[PlanItem],
) -> String {
    let mut md = String::new();
    let _ = writeln!(md, "# Security test plan: {}\n", inline(project));
    let _ = writeln!(
        md,
        "> ⚠️ Only test systems you own or have explicit written permission to test.\n"
    );
    if let Some(url) = url {
        let _ = writeln!(md, "**Target:** <{url}>  ");
    }
    if !tags.is_empty() {
        let _ = writeln!(md, "**Stack:** {}  ", inline(&tags.join(", ")));
    }
    if !description.is_empty() {
        let _ = writeln!(md, "\n**Description:**\n");
        for line in description.lines() {
            let _ = writeln!(md, "> {line}");
        }
    }

    let minutes: u32 = items
        .iter()
        .flat_map(|i| &i.actions)
        .map(|a| a.est_minutes)
        .sum();
    let _ = writeln!(
        md,
        "\n## Summary\n\n{} tests, about {} minutes of automated scanning.\n",
        items.len(),
        minutes
    );
    let _ = writeln!(md, "| Priority | Test | Why | Tools |\n|---|---|---|---|");
    for item in items {
        let tools: Vec<&str> = item.actions.iter().map(|a| a.tool.as_str()).collect();
        let tools = if tools.is_empty() {
            "Manual".to_string()
        } else {
            tools.join(", ")
        };
        let flag = if item.active { " ⚡ active" } else { "" };
        let _ = writeln!(
            md,
            "| {} | {}{} | {} | {} |",
            severity_label(item.severity),
            inline(&item.title),
            flag,
            inline(&item.why.join(", ")),
            tools
        );
    }

    for (n, item) in items.iter().enumerate() {
        let _ = writeln!(md, "\n## {}. {}\n", n + 1, inline(&item.title));
        let _ = writeln!(md, "**Priority:** {}  ", severity_label(item.severity));
        if !item.references.is_empty() {
            let _ = writeln!(md, "**References:** {}  ", item.references.join(", "));
        }
        let _ = writeln!(md, "**Why:** {}\n", inline(&item.why.join(", ")));
        if item.active {
            let _ = writeln!(
                md,
                "> ⚡ **Active test.** Sends attack payloads to the target. Only run it against a test environment.\n"
            );
        }
        let _ = writeln!(md, "{}\n", item.description);
        if let Some(expected) = &item.expected_secure_behavior {
            let _ = writeln!(md, "**Expected secure behavior:** {expected}\n");
        }
        if item.actions.is_empty() {
            let _ = writeln!(md, "_Manual test: no automated tool._");
        }
        for action in &item.actions {
            let _ = writeln!(
                md,
                "**{}** ({}, {}, {}, ~{} min)\n\n```sh\n{}\n```\n",
                action.title,
                action.tool,
                if action.input == "url" { "URL" } else { "code" },
                action.mode,
                action.est_minutes,
                action.command
            );
        }
    }
    md
}
