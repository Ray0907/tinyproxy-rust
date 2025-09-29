use crate::config::Config;
use crate::error::{ProxyError, ProxyResult};
use log::{debug, warn};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub struct Filter {
    enabled: bool,
    rules: Vec<FilterRule>,
    case_sensitive: bool,
    extended: bool,
}

#[derive(Clone)]
enum FilterRule {
    Exact(String),
    Regex(Regex),
    Domain(String),
}

impl Filter {
    pub fn new(config: &Config) -> Self {
        let mut filter = Self {
            enabled: config.filter_urls,
            rules: Vec::new(),
            case_sensitive: config.filter_casesensitive,
            extended: config.filter_extended,
        };

        if config.filter_urls {
            if let Some(filter_file) = &config.filter_file {
                if let Err(e) = filter.load_filter_file(filter_file) {
                    warn!("Failed to load filter file {}: {}", filter_file, e);
                }
            }
        }

        filter
    }

    pub fn is_allowed(&self, url: &str) -> ProxyResult<bool> {
        if !self.enabled {
            return Ok(true);
        }

        let url_to_check = if self.case_sensitive {
            url.to_string()
        } else {
            url.to_lowercase()
        };

        for rule in &self.rules {
            if self.matches_rule(rule, &url_to_check) {
                debug!("URL {} blocked by filter rule: {:?}", url, rule);
                return Ok(false);
            }
        }

        debug!("URL {} allowed by filter", url);
        Ok(true)
    }

    fn load_filter_file(&mut self, filename: &str) -> ProxyResult<()> {
        let file = File::open(filename).map_err(|e| {
            ProxyError::Config(format!("Cannot open filter file {}: {}", filename, e))
        })?;

        let reader = BufReader::new(file);

        for (line_num, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| {
                ProxyError::Config(format!(
                    "Error reading filter file line {}: {}",
                    line_num + 1,
                    e
                ))
            })?;

            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let rule_text = if self.case_sensitive {
                line.to_string()
            } else {
                line.to_lowercase()
            };

            let rule = if self.extended {
                // Try to compile as regex
                match Regex::new(&rule_text) {
                    Ok(regex) => FilterRule::Regex(regex),
                    Err(_) => {
                        // Fall back to exact match if regex compilation fails
                        warn!(
                            "Invalid regex pattern on line {}: {}, treating as exact match",
                            line_num + 1,
                            line
                        );
                        FilterRule::Exact(rule_text)
                    }
                }
            } else if line.starts_with('.') {
                // Domain rule (e.g., .example.com)
                FilterRule::Domain(rule_text)
            } else {
                // Exact match
                FilterRule::Exact(rule_text)
            };

            self.rules.push(rule);
        }

        debug!("Loaded {} filter rules from {}", self.rules.len(), filename);
        Ok(())
    }

    fn matches_rule(&self, rule: &FilterRule, url: &str) -> bool {
        match rule {
            FilterRule::Exact(pattern) => url.contains(pattern),
            FilterRule::Regex(regex) => regex.is_match(url),
            FilterRule::Domain(domain) => {
                // Extract hostname from URL
                if let Ok(parsed_url) = url::Url::parse(url) {
                    if let Some(host) = parsed_url.host_str() {
                        let host = if self.case_sensitive {
                            host.to_string()
                        } else {
                            host.to_lowercase()
                        };

                        // Check if the host ends with the domain (for .example.com rules)
                        if domain.starts_with('.') {
                            host.ends_with(domain) || host == &domain[1..]
                        } else {
                            host == *domain
                        }
                    } else {
                        false
                    }
                } else {
                    // If URL parsing fails, fall back to substring matching
                    url.contains(domain)
                }
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl std::fmt::Debug for FilterRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FilterRule::Exact(pattern) => write!(f, "Exact({})", pattern),
            FilterRule::Regex(regex) => write!(f, "Regex({})", regex.as_str()),
            FilterRule::Domain(domain) => write!(f, "Domain({})", domain),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_filter_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", content).unwrap();
        file
    }

    #[test]
    fn test_filter_disabled() {
        let config = Config::default(); // filter_urls is false by default
        let filter = Filter::new(&config);

        assert!(!filter.is_enabled());
        assert!(filter.is_allowed("http://example.com").unwrap());
    }

    #[test]
    fn test_exact_match_filter() {
        let filter_content = "ads\ntracker\n# This is a comment\n\nbadsite.com";
        let filter_file = create_test_filter_file(filter_content);

        let mut config = Config::default();
        config.filter_urls = true;
        config.filter_file = Some(filter_file.path().to_string_lossy().to_string());

        let filter = Filter::new(&config);

        assert!(filter.is_enabled());
        assert_eq!(filter.rule_count(), 3); // ads, tracker, badsite.com

        assert!(!filter.is_allowed("http://ads.example.com").unwrap());
        assert!(!filter.is_allowed("http://tracker.evil.com").unwrap());
        assert!(!filter.is_allowed("http://badsite.com").unwrap());
        assert!(filter.is_allowed("http://goodsite.com").unwrap());
    }

    #[test]
    fn test_domain_filter() {
        let filter_content = ".evil.com\n.ads.net";
        let filter_file = create_test_filter_file(filter_content);

        let mut config = Config::default();
        config.filter_urls = true;
        config.filter_file = Some(filter_file.path().to_string_lossy().to_string());

        let filter = Filter::new(&config);

        assert!(!filter.is_allowed("http://sub.evil.com").unwrap());
        assert!(!filter.is_allowed("http://evil.com").unwrap());
        assert!(!filter.is_allowed("http://tracker.ads.net").unwrap());
        assert!(filter.is_allowed("http://good.com").unwrap());
    }

    #[test]
    fn test_regex_filter() {
        let filter_content = r"ads\d+\.com\n.*tracker.*";
        let filter_file = create_test_filter_file(filter_content);

        let mut config = Config::default();
        config.filter_urls = true;
        config.filter_extended = true;
        config.filter_file = Some(filter_file.path().to_string_lossy().to_string());

        let filter = Filter::new(&config);

        assert!(!filter.is_allowed("http://ads123.com").unwrap());
        assert!(!filter.is_allowed("http://mytracker.evil.com").unwrap());
        assert!(filter.is_allowed("http://ads.com").unwrap()); // No digits
        assert!(filter.is_allowed("http://good.com").unwrap());
    }

    #[test]
    fn test_case_sensitivity() {
        let filter_content = "ADS\nTracker";
        let filter_file = create_test_filter_file(filter_content);

        // Case insensitive (default)
        let mut config = Config::default();
        config.filter_urls = true;
        config.filter_casesensitive = false;
        config.filter_file = Some(filter_file.path().to_string_lossy().to_string());

        let filter = Filter::new(&config);

        assert!(!filter.is_allowed("http://ads.example.com").unwrap());
        assert!(!filter.is_allowed("http://TRACKER.com").unwrap());

        // Case sensitive
        config.filter_casesensitive = true;
        let filter = Filter::new(&config);

        assert!(filter.is_allowed("http://ads.example.com").unwrap()); // 'ads' != 'ADS'
        assert!(!filter.is_allowed("http://ADS.example.com").unwrap());
    }
}
