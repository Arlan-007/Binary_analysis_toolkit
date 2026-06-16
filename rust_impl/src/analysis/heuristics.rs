use std::collections::HashSet;
use regex::Regex;

use crate::models::Finding;
use crate::models::Import;
use crate::data::import_signature::IMPORT_RULES;
use crate::data::url_signature::URL_REGEX;
use crate::data::url_signature::EXECUTABLE_EXTENSIONS;
use crate::models::Severity;

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