use std::collections::HashSet;
use regex::Regex;

use crate::models::{Finding, Import, Severity, Section};
use crate::data::import_signature::IMPORT_RULES;
use crate::data::url_signature::{URL_REGEX, EXECUTABLE_EXTENSIONS};
use crate::data::ip_signature::{IPV4_REGEX, PRIVATE_IP_PREFIXES, LOCAL_IPS};
use crate::data::credential_signature::CREDENTIAL_RULES;
use crate::data::section_signature::SECTION_RULES;

pub fn suspicious_imports(imports: &[Import]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for import in imports {
        for rule in IMPORT_RULES {
            if import.function == rule.function {
                findings.push(Finding {
                    severity: rule.severity.clone(),
                    title: rule.function.to_string(),
                    category: rule.category.to_string(),
                    description: rule.description.to_string(),
                });
            }
        }
    }
    findings
}

pub fn suspicious_url(strings: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut found: HashSet<String> = HashSet::new();

    let re = Regex::new(URL_REGEX).unwrap();
    for string in strings {
        for m in re.find_iter(string) {
            let url = m.as_str().to_string();
            let url_lower = url.to_lowercase();
            let mut severity_ = Severity::Medium;

            for ext in EXECUTABLE_EXTENSIONS {
                if url_lower.contains(ext) {
                    severity_ = Severity::High;
                    break;
                }
            }

            if found.insert(url.clone()) {
                findings.push(Finding {
                    severity: severity_,
                    category: "Networking".to_string(),
                    title: url.clone(),
                    description: format!("Found URL: {}", url),
                });
            }
        }
    }
    findings
}

pub fn suspicious_ip(strings: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut found: HashSet<String> = HashSet::new();

    let re = Regex::new(IPV4_REGEX).unwrap();
    for string in strings {
        for m in re.find_iter(string) {
            let ip = m.as_str().to_string();

            if found.insert(ip.clone()) {
                let severity = if LOCAL_IPS.contains(&ip.as_str()) {
                    Severity::Low
                } else if PRIVATE_IP_PREFIXES
                    .iter()
                    .any(|prefix| ip.starts_with(prefix))
                {
                    Severity::Low
                } else {
                    Severity::Medium
                };
                findings.push(Finding {
                    severity,
                    category: "Networking".to_string(),
                    title: ip.clone(),
                    description: format!(
                        "Found embedded IPv4 address: {}",
                        ip
                    ),
                });
            }
        }
    }
    findings
}


pub fn suspicious_credentials(strings: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut found: HashSet<String> = HashSet::new();

    let compiled_rules: Vec<_> = CREDENTIAL_RULES
        .iter()
        .map(|rule| {
            let regexes = rule
                .patterns
                .iter()
                .map(|pattern| Regex::new(pattern).unwrap())
                .collect::<Vec<_>>();

            (regexes, rule.severity.clone(), rule.category, rule.description)
        })
        .collect();

    for string in strings {
        for (regexes, severity, category, description) in &compiled_rules {
            if regexes.iter().any(|re| re.is_match(string)) {
                if found.insert(string.clone()) {
                    findings.push(Finding {
                        severity: severity.clone(),
                        title: format!("Credential Indicator: {}", category),
                        category: category.to_string(),
                        description: format!("{} Matched string: {}", description, string),
                    });
                }
            }
        }
    }
    findings
}

pub fn suspicious_sections(sections: &[Section]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for section in sections {
        let section_name = section.name.to_lowercase();

        for rule in SECTION_RULES {
            if rule
                .names
                .iter()
                .any(|name| section_name == *name || section_name.contains(name))
            {
                if seen.insert(section_name.clone()) {
                    findings.push(Finding {
                        severity: rule.severity.clone(),
                        title: format!("Suspicious Section: {}", section.name),
                        category: rule.category.to_string(),
                        description: format!(
                            "{} Matched section: {}",
                            rule.description, section.name
                        ),
                    });
                }
            }
        }
    }
    findings
}