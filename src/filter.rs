use crate::config::Config;
use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use std::fs;

pub struct Filter {
    enabled: bool,
    urls: bool,
    case_sensitive: bool,
    default_deny: bool,
    rules: Vec<Rule>,
}

enum Rule {
    Literal(String),
    Regex(Regex),
}

impl Filter {
    /// Called only at startup; missing files and invalid regexes fail closed.
    pub fn new(config: &Config) -> Result<Self> {
        let mut filter = Self {
            enabled: config.filter_file.is_some(),
            urls: config.filter_urls,
            case_sensitive: config.filter_casesensitive,
            default_deny: config.filter_default_deny,
            rules: Vec::new(),
        };
        if let Some(path) = &config.filter_file {
            let text = fs::read_to_string(path).context("Cannot read Filter file")?;
            for (index, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let rule = if config.filter_extended {
                    Rule::Regex(
                        RegexBuilder::new(line)
                            .case_insensitive(!config.filter_casesensitive)
                            .size_limit(1 << 20)
                            .build()
                            .with_context(|| {
                                format!("Invalid regex at filter line {}", index + 1)
                            })?,
                    )
                } else {
                    Rule::Literal(if config.filter_casesensitive {
                        line.to_owned()
                    } else {
                        line.to_ascii_lowercase()
                    })
                };
                filter.rules.push(rule);
            }
        }
        Ok(filter)
    }

    /// CONNECT is always checked by authority host; encrypted paths are opaque.
    pub fn is_allowed(&self, host: &str, url: &str, connect: bool) -> bool {
        if !self.enabled {
            return true;
        }
        let match_url = self.urls && !connect;
        let target = if match_url {
            url
        } else {
            host.trim_end_matches('.')
        };
        let target = if self.case_sensitive {
            target.to_owned()
        } else {
            target.to_ascii_lowercase()
        };
        let matched = self.rules.iter().any(|rule| match rule {
            Rule::Regex(regex) => regex.is_match(&target),
            Rule::Literal(pattern) if match_url => target.contains(pattern),
            Rule::Literal(pattern) => {
                let domain = pattern.trim_start_matches('.').trim_end_matches('.');
                target == domain
                    || target
                        .strip_suffix(domain)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        });
        if self.default_deny {
            matched
        } else {
            !matched
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}
