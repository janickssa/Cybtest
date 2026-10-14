//! Tag vocabulary, rule base and tool catalog, loaded from YAML at startup.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub use common::{CatalogAction, Severity};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TagDef {
    pub id: String,
    pub label: String,
    pub category: String,
    /// Words in a description that suggest this tag.
    #[serde(default, skip_serializing)]
    pub keywords: Vec<String>,
    /// Tags that follow from this one, e.g. `fw:axum` implies `lang:rust`.
    #[serde(default, skip_serializing)]
    pub implies: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct When {
    #[serde(default)]
    pub all: Vec<String>,
    #[serde(default)]
    pub any: Vec<String>,
    #[serde(default)]
    pub none: Vec<String>,
}

impl When {
    /// Returns the tags that made the rule match, or `None` if it doesn't.
    pub fn matches(&self, tags: &HashSet<&str>) -> Option<Vec<String>> {
        if !self.all.iter().all(|t| tags.contains(t.as_str()))
            || self.none.iter().any(|t| tags.contains(t.as_str()))
        {
            return None;
        }
        let any: Vec<String> = self
            .any
            .iter()
            .filter(|t| tags.contains(t.as_str()))
            .cloned()
            .collect();
        if !self.any.is_empty() && any.is_empty() {
            return None;
        }
        Some(self.all.iter().cloned().chain(any).collect())
    }

    fn tags(&self) -> impl Iterator<Item = &String> {
        self.all.iter().chain(&self.any).chain(&self.none)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleAction {
    pub id: String,
    #[serde(default)]
    pub requires: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub when: When,
    pub severity: Severity,
    #[serde(default)]
    pub references: Vec<String>,
    pub description: String,
    pub expected_secure_behavior: Option<String>,
    #[serde(default)]
    pub actions: Vec<RuleAction>,
}

pub struct Knowledge {
    pub tags: Vec<TagDef>,
    pub rules: Vec<Rule>,
    pub catalog: HashMap<String, CatalogAction>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

const TAGS_FILE: &str = "tags.yaml";

fn load_dir<T: for<'de> Deserialize<'de>>(dir: &Path, skip: &str) -> Result<Vec<T>, String> {
    let mut paths: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
        .filter(|p| p.file_name().is_some_and(|n| n != skip))
        .collect();
    paths.sort();
    let mut out = Vec::new();
    for path in paths {
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        match serde_yaml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))? {
            OneOrMany::One(item) => out.push(item),
            OneOrMany::Many(items) => out.extend(items),
        }
    }
    Ok(out)
}

impl Knowledge {
    /// Loads `rules/tags.yaml`, every other YAML file in `rules/` (one rule or a
    /// list of rules per file) and every action in `catalog/`, then checks that
    /// they reference each other consistently.
    pub fn load(rules_dir: &Path, catalog_dir: &Path) -> Result<Self, String> {
        let tags_path = rules_dir.join(TAGS_FILE);
        let tags: Vec<TagDef> = serde_yaml::from_str(
            &fs::read_to_string(&tags_path).map_err(|e| format!("{}: {e}", tags_path.display()))?,
        )
        .map_err(|e| format!("{}: {e}", tags_path.display()))?;
        let rules: Vec<Rule> = load_dir(rules_dir, TAGS_FILE)?;
        let catalog = common::load_catalog(catalog_dir)?;
        let k = Self {
            tags,
            rules,
            catalog,
        };
        k.validate()?;
        Ok(k)
    }

    fn validate(&self) -> Result<(), String> {
        let tag_ids: HashSet<&str> = self.tags.iter().map(|t| t.id.as_str()).collect();
        for tag in &self.tags {
            if let Some(bad) = tag.implies.iter().find(|t| !tag_ids.contains(t.as_str())) {
                return Err(format!("tag {}: implies unknown tag {bad}", tag.id));
            }
        }
        let mut seen = HashSet::new();
        for rule in &self.rules {
            if !seen.insert(&rule.id) {
                return Err(format!("duplicate rule id {}", rule.id));
            }
            if let Some(bad) = rule.when.tags().find(|t| !tag_ids.contains(t.as_str())) {
                return Err(format!("rule {}: unknown tag {bad}", rule.id));
            }
            if let Some(bad) = rule
                .actions
                .iter()
                .find(|a| !self.catalog.contains_key(&a.id))
            {
                return Err(format!("rule {}: unknown action {}", rule.id, bad.id));
            }
        }
        Ok(())
    }

    pub fn tag_label(&self, id: &str) -> String {
        self.tags
            .iter()
            .find(|t| t.id == id)
            .map_or_else(|| id.to_string(), |t| t.label.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTag {
    pub id: String,
    pub label: String,
    pub evidence: String,
}

/// True if `needle` occurs in `haystack` with no letter or digit directly
/// before or after it, so "go" doesn't match "google".
fn contains_word(haystack: &str, needle: &str) -> bool {
    let is_word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric());
    haystack.match_indices(needle).any(|(i, _)| {
        !is_word(haystack[..i].chars().next_back())
            && !is_word(haystack[i + needle.len()..].chars().next())
    })
}

impl Knowledge {
    /// Suggests tags from a free-text description and an optional target URL.
    pub fn detect(&self, description: &str, url: Option<&url::Url>) -> Vec<DetectedTag> {
        let mut found: BTreeMap<String, String> = BTreeMap::new();
        if let Some(url) = url {
            found.insert("input:url".into(), format!("Target URL {url}"));
            let proto = format!("proto:{}", url.scheme());
            found.insert(proto, format!("URL scheme is {}", url.scheme()));
        }
        let text = description.to_lowercase();
        for tag in &self.tags {
            if let Some(kw) = tag.keywords.iter().find(|kw| contains_word(&text, kw)) {
                found
                    .entry(tag.id.clone())
                    .or_insert_with(|| format!("\"{kw}\" in description"));
            }
        }
        self.with_implied(found)
    }

    /// Adds the tags implied by `found` (id → evidence) and attaches labels.
    pub fn with_implied(&self, mut found: BTreeMap<String, String>) -> Vec<DetectedTag> {
        self.add_implied(&mut found);
        found
            .into_iter()
            .map(|(id, evidence)| DetectedTag {
                label: self.tag_label(&id),
                id,
                evidence,
            })
            .collect()
    }

    fn add_implied(&self, found: &mut BTreeMap<String, String>) {
        loop {
            let new: Vec<(String, String)> = self
                .tags
                .iter()
                .filter(|t| found.contains_key(&t.id))
                .flat_map(|t| t.implies.iter().map(move |i| (i, &t.label)))
                .filter(|(i, _)| !found.contains_key(*i))
                .map(|(i, label)| (i.clone(), format!("implied by {label}")))
                .collect();
            if new.is_empty() {
                return;
            }
            found.extend(new);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn knowledge() -> Knowledge {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        Knowledge::load(&root.join("rules"), &root.join("catalog")).unwrap()
    }

    #[test]
    fn shipped_rules_and_catalog_are_valid() {
        let k = knowledge();
        assert!(k.rules.len() >= 30, "only {} rules", k.rules.len());
    }

    #[test]
    fn when_all_any_none() {
        let w = When {
            all: vec!["lib:sqlx".into()],
            any: vec![],
            none: vec!["db:orm".into()],
        };
        assert!(w.matches(&HashSet::from(["lib:sqlx"])).is_some());
        assert!(w.matches(&HashSet::from(["lib:sqlx", "db:orm"])).is_none());
        let any = When {
            any: vec!["a".into(), "b".into()],
            ..Default::default()
        };
        assert_eq!(
            any.matches(&HashSet::from(["b", "c"])),
            Some(vec!["b".into()])
        );
        assert!(any.matches(&HashSet::from(["c"])).is_none());
    }

    #[test]
    fn detects_keywords_urls_and_implied_tags() {
        let k = knowledge();
        let url = url::Url::parse("https://internaltest.example.dk").unwrap();
        let tags = k.detect(
            "Axum backend with JWT login, deployed on Google Cloud",
            Some(&url),
        );
        let ids: Vec<&str> = tags.iter().map(|t| t.id.as_str()).collect();
        for want in [
            "fw:axum",
            "lang:rust",
            "auth:jwt",
            "input:url",
            "proto:https",
        ] {
            assert!(ids.contains(&want), "missing {want} in {ids:?}");
        }
        assert!(
            !ids.contains(&"lang:go"),
            "\"go\" matched inside \"google\""
        );
    }
}
