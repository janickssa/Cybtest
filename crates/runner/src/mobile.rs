//! Built-in check of mobile app configuration: AndroidManifest.xml and iOS
//! Info.plist settings that weaken the app's security (MASVS).

use std::fs;
use std::path::{Path, PathBuf};

use common::{Finding, Severity};

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "build",
    "Pods",
    ".gradle",
    "DerivedData",
    "target",
];
const MAX_FILE: u64 = 2 * 1024 * 1024;
const MASVS: &str = "https://mas.owasp.org/MASVS/";

fn files_named(root: &Path, wanted: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            match entry.file_type() {
                Ok(t) if t.is_dir() && !SKIP_DIRS.contains(&name.as_str()) => stack.push(path),
                Ok(t) if t.is_file() && name.eq_ignore_ascii_case(wanted) => out.push(path),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

fn line_of(text: &str, index: usize) -> usize {
    text[..index].matches('\n').count() + 1
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let start = tag.find(&format!("{name}=\""))? + name.len() + 2;
    tag[start..].split('"').next()
}

struct Ctx<'a> {
    findings: Vec<Finding>,
    rel: &'a str,
}

impl Ctx<'_> {
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        rule: &str,
        title: &str,
        severity: Severity,
        line: usize,
        message: &str,
        help: &str,
        snippet: &str,
    ) {
        self.findings.push(Finding {
            tool: "built-in".into(),
            rule_id: rule.into(),
            title: title.into(),
            severity,
            location: Some(format!("{}:{line}", self.rel)),
            message: message.into(),
            snippet: Some(snippet.trim().chars().take(300).collect()),
            help: Some(help.into()),
            help_url: Some(MASVS.into()),
        });
    }
}

fn android(text: &str, ctx: &mut Ctx) {
    let flags = [
        ("android:debuggable=\"true\"", "android-debuggable", "App is debuggable", Severity::High,
         "A debuggable app lets anyone with the device attach a debugger and read its memory and data.",
         "Remove android:debuggable from the manifest; release builds set it automatically."),
        ("android:allowBackup=\"true\"", "android-allow-backup", "App data can be backed up", Severity::Medium,
         "With backups allowed, the app's private files can be copied off the device with adb.",
         "Set android:allowBackup=\"false\", or exclude sensitive files with data extraction rules."),
        ("android:usesCleartextTraffic=\"true\"", "android-cleartext-traffic", "Cleartext HTTP traffic allowed", Severity::Medium,
         "The app may send data over unencrypted HTTP, where anyone on the network can read or change it.",
         "Remove usesCleartextTraffic and use HTTPS, or limit exceptions with a network security config."),
    ];
    for (needle, rule, title, severity, message, help) in flags {
        if let Some(i) = text.find(needle) {
            ctx.add(
                rule,
                title,
                severity,
                line_of(text, i),
                message,
                help,
                needle,
            );
        }
    }
    for kind in [
        "activity",
        "activity-alias",
        "service",
        "receiver",
        "provider",
    ] {
        let open = format!("<{kind} ");
        let mut from = 0;
        while let Some(pos) = text[from..].find(&open) {
            let start = from + pos;
            let end = text[start..]
                .find('>')
                .map_or(text.len(), |e| start + e + 1);
            let tag = &text[start..end];
            from = end;
            if attr(tag, "android:exported") != Some("true")
                || attr(tag, "android:permission").is_some()
            {
                continue;
            }
            let name = attr(tag, "android:name").unwrap_or("?");
            // The launcher activity must be exported; it isn't a finding by itself.
            let block_end = text[end..]
                .find(&format!("</{kind}>"))
                .map_or(end, |e| end + e);
            if text[end..block_end].contains("android.intent.category.LAUNCHER") {
                continue;
            }
            ctx.add(
                "android-exported-component",
                &format!("Exported {kind} without a permission: {name}"),
                Severity::Low,
                line_of(text, start),
                "Other apps on the device can start or bind to this component and send it data.",
                "Set android:exported=\"false\" if other apps don't need it, or protect it with android:permission, and validate all incoming intents.",
                tag,
            );
        }
    }
}

fn ios(text: &str, ctx: &mut Ctx) {
    let keys = [
        (
            "NSAllowsArbitraryLoads",
            "ios-ats-arbitrary-loads",
            "App Transport Security disabled",
            Severity::Medium,
            "NSAllowsArbitraryLoads lets the app load any URL over unencrypted HTTP.",
        ),
        (
            "NSExceptionAllowsInsecureHTTPLoads",
            "ios-ats-insecure-domain",
            "Insecure HTTP allowed for a domain",
            Severity::Low,
            "An App Transport Security exception allows plain HTTP for at least one domain.",
        ),
    ];
    for (key, rule, title, severity, message) in keys {
        let mut from = 0;
        let tag = format!("<key>{key}</key>");
        while let Some(pos) = text[from..].find(&tag) {
            let start = from + pos;
            from = start + tag.len();
            let after = &text[from..text.len().min(from + 80)];
            if after.trim_start().starts_with("<true/>") {
                ctx.add(
                    rule,
                    title,
                    severity,
                    line_of(text, start),
                    message,
                    "Use HTTPS everywhere and remove the App Transport Security exception.",
                    &format!("<key>{key}</key> <true/>"),
                );
                break;
            }
        }
    }
}

/// Checks every AndroidManifest.xml and Info.plist in the project.
pub fn check(src: &Path) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut log = Vec::new();
    for (file, is_android) in [("AndroidManifest.xml", true), ("Info.plist", false)] {
        for path in files_named(src, file) {
            let rel = path
                .strip_prefix(src)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            if fs::metadata(&path).map_or(true, |m| m.len() > MAX_FILE) {
                log.push(format!("Skipped {rel} (too large)"));
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else {
                log.push(format!(
                    "Skipped {rel} (binary or unreadable; only XML plists are checked)"
                ));
                continue;
            };
            let mut ctx = Ctx {
                findings: Vec::new(),
                rel: &rel,
            };
            if is_android {
                android(&text, &mut ctx);
            } else {
                ios(&text, &mut ctx);
            }
            log.push(format!("Checked {rel}: {} findings", ctx.findings.len()));
            findings.extend(ctx.findings);
        }
    }
    if log.is_empty() {
        log.push("No AndroidManifest.xml or Info.plist found".into());
    }
    (findings, log)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_manifest_and_plist_issues() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir_all(root.join("app/src/main")).unwrap();
        fs::create_dir_all(root.join("ios/App")).unwrap();
        fs::write(
            root.join("app/src/main/AndroidManifest.xml"),
            r#"<manifest>
  <application android:allowBackup="true" android:debuggable="true">
    <activity android:name=".Main" android:exported="true">
      <intent-filter><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
    </activity>
    <receiver android:name=".Sync" android:exported="true"></receiver>
    <service android:name=".Safe" android:exported="true" android:permission="x.PERM"></service>
  </application>
</manifest>"#,
        )
        .unwrap();
        fs::write(
            root.join("ios/App/Info.plist"),
            "<dict>\n<key>NSAppTransportSecurity</key>\n<dict>\n<key>NSAllowsArbitraryLoads</key>\n<true/>\n</dict>\n</dict>",
        )
        .unwrap();
        let (findings, _) = check(root);
        let rules: Vec<(&str, Option<&str>)> = findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.location.as_deref()))
            .collect();
        assert_eq!(
            rules,
            vec![
                (
                    "android-debuggable",
                    Some("app/src/main/AndroidManifest.xml:2")
                ),
                (
                    "android-allow-backup",
                    Some("app/src/main/AndroidManifest.xml:2")
                ),
                (
                    "android-exported-component",
                    Some("app/src/main/AndroidManifest.xml:6")
                ),
                ("ios-ats-arbitrary-loads", Some("ios/App/Info.plist:4")),
            ]
        );
        assert_eq!(
            findings[2].title,
            "Exported receiver without a permission: .Sync"
        );
    }
}
