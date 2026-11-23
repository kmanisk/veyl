//! Bounded, non-executable instruction packages under an operator-owned root.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::http::admission::Configuration;
use crate::protected_paths::{is_mandatory, validate_path};
use crate::tools::MutationRoot;
use crate::tools::registry::{Tool, tool_text};

const MAX_SKILLS: usize = 128;

pub(crate) struct Skills {
    root: MutationRoot,
    pub(crate) disabled: BTreeSet<String>,
}

impl Skills {
    pub(crate) fn load(
        config: &Path,
        document: &Value,
        settings: &Configuration,
    ) -> Result<Option<Self>, String> {
        let Some(path) = document.get("skills_dir") else {
            if document.get("skills_disabled").is_some()
                || settings
                    .clients
                    .iter()
                    .any(|client| !client.skills.is_empty())
            {
                return Err("Skill grants require skills_dir".into());
            }
            return Ok(None);
        };
        let path = PathBuf::from(path.as_str().ok_or("Invalid skills directory")?);
        validate_path(&path)?;
        if is_mandatory(config, settings, &path)
            || settings.clients.iter().any(|client| {
                overlaps(&path, &client.root)
                    || client
                        .extra_roots
                        .iter()
                        .any(|root| overlaps(&path, root.path()))
            })
        {
            return Err(
                "Skills directory must be separate from gateway state and workspaces".into(),
            );
        }
        let root = MutationRoot::open_owned(&path)
            .map_err(|_| "Unsafe or unavailable skills directory")?;
        Ok(Some(Self {
            root,
            disabled: parse_names(document.get("skills_disabled"))?,
        }))
    }

    pub(crate) fn read(&self, name: &str) -> Result<Skill, &'static str> {
        if !valid_name(name) {
            return Err("Invalid skill name");
        }
        let document = self
            .root
            .read(&format!("{name}/SKILL.md"))
            .map_err(|_| "Skill unavailable")?;
        Skill::parse(name, document)
    }

    pub(crate) fn call(
        &self,
        tool: Tool,
        args: Option<&Value>,
        grants: &BTreeSet<String>,
    ) -> Value {
        let args = match args {
            Some(Value::Object(args)) => Some(args),
            None => None,
            _ => return tool_text(true, "Invalid skill tool arguments"),
        };
        match tool {
            Tool::SkillsList if args.is_none_or(serde_json::Map::is_empty) => {
                let mut skills = Vec::new();
                let mut bytes = 0;
                for name in grants.difference(&self.disabled) {
                    if let Ok(skill) = self.read(name) {
                        let metadata = json!({
                            "name": name, "description": skill.description, "version": skill.version
                        });
                        bytes += metadata.to_string().len() + 1;
                        if bytes > 60_000 {
                            return tool_text(true, "Skill metadata exceeds the response limit");
                        }
                        skills.push(metadata);
                    }
                }
                tool_text(false, &json!({ "skills": skills }).to_string())
            }
            Tool::SkillsRead => {
                let name = args
                    .filter(|args| args.len() == 1)
                    .and_then(|args| args.get("name"))
                    .and_then(Value::as_str);
                let Some(name) = name.filter(|name| {
                    valid_name(name) && grants.contains(*name) && !self.disabled.contains(*name)
                }) else {
                    return tool_text(true, "Skill unavailable or not granted");
                };
                match self.read(name) {
                    Ok(skill) => tool_text(false, &skill.document),
                    Err(error) => tool_text(true, error),
                }
            }
            _ => tool_text(true, "Invalid skill tool arguments"),
        }
    }
}

pub(crate) struct Skill {
    document: String,
    description: String,
    version: Option<String>,
}

impl Skill {
    fn parse(name: &str, document: String) -> Result<Self, &'static str> {
        const INVALID: &str = "Invalid skill metadata";
        let mut lines = document.lines();
        if lines.next() != Some("---") {
            return Err(INVALID);
        }
        let (mut id, mut description, mut version) = (None, None, None);
        let mut closed = false;
        for line in lines.by_ref().take(32) {
            if line == "---" {
                closed = true;
                break;
            }
            let (key, value) = line.split_once(':').ok_or(INVALID)?;
            let value = value.trim();
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(INVALID);
            }
            match key {
                "name" if id.is_none() => id = Some(value),
                "description" if description.is_none() && value.len() <= 256 => {
                    description = Some(value.to_owned());
                }
                "version" if version.is_none() && value.len() <= 40 => {
                    version = Some(value.to_owned());
                }
                _ => return Err(INVALID),
            }
        }
        if !closed || id != Some(name) || !lines.any(|line| !line.trim().is_empty()) {
            return Err(INVALID);
        }
        Ok(Self {
            document,
            description: description.ok_or(INVALID)?,
            version,
        })
    }
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub(crate) fn parse_names(raw: Option<&Value>) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    let Some(raw) = raw else { return Ok(names) };
    let values = raw.as_array().ok_or("Expected a skill name array")?;
    if values.len() > MAX_SKILLS {
        return Err("Too many skill names".into());
    }
    for item in values {
        let name = item
            .as_str()
            .filter(|name| valid_name(name))
            .ok_or("Invalid skill name")?;
        if !names.insert(name.to_string()) {
            return Err("Duplicate skill name".into());
        }
    }
    Ok(names)
}

fn overlaps(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}
