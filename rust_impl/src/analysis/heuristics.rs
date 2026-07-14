use std::collections::HashSet;
use regex::Regex;

use crate::models::{Finding, Import, Severity, Section};
use crate::data::import_signature::IMPORT_RULES;
use crate::data::url_signature::{URL_REGEX, EXECUTABLE_EXTENSIONS};
use crate::data::ip_signature::{IPV4_REGEX, PRIVATE_IP_PREFIXES, LOCAL_IPS};
use crate::data::credential_signature::{CREDENTIAL_RULES, is_plausible};
use crate::data::section_signature::SECTION_RULES;
use crate::data::encoding_signature::{is_base64, decode_base64, is_hex, decode_hex};
use crate::analysis::entropy::{calculate_entropy, max_entropy_for_length};
use crate::data::section_entropy_signature::{is_entropy_suspicious, max_expected_entropy_for, MIN_ENTROPY_SECTION_SIZE, is_known_packer_section};

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

            (regexes, rule)
        })
        .collect();

    for string in strings {
        for (regexes, rule) in &compiled_rules {
            let matched = if rule.requires_value {
                regexes.iter().any(|re| {
                    re.captures(string)
                        .and_then(|caps| caps.get(1))
                        .map(|value| is_plausible(value.as_str()))
                        .unwrap_or(false)
                })
            } else {
                regexes.iter().any(|re| re.is_match(string))
            };

            if matched {
                if found.insert(string.clone()) {
                    findings.push(Finding {
                        severity: rule.severity.clone(),
                        title: format!("Credential Indicator: {}", rule.category),
                        category: rule.category.to_string(),
                        description: format!(
                            "{} Matched string: {}",
                            rule.description, string
                        ),
                    });
                }
                break;
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

pub fn detect_encoded_strings(strings: &[String], ) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut found: HashSet<String> = HashSet::new();

    for s in strings {
        if found.insert(s.clone()) {
            if is_base64(s) {
                let decoded = decode_base64(s).unwrap_or_else(|| "<non-printable>".to_string());
                findings.push(Finding {
                    severity: Severity::Low,
                    title: "Base64 Encoded String".to_string(),
                    category: "Encoded String".to_string(),
                    description: format!(
                        "Base64 string detected\nEncoded: {}\nDecoded: {}",
                        s,
                        decoded
                    ),
                });
            }

            if is_hex(s) {
                let decoded = decode_hex(s).unwrap_or_else(|| "<non-printable>".to_string());
                findings.push(Finding {
                    severity: Severity::Low,
                    title: "Hex Encoded String".to_string(),
                    category: "Encoded String".to_string(),
                    description: format!(
                        "Hex encoded string detected\nEncoded: {}\nDecoded: {}",
                        s,
                        decoded
                    ),
                });
            }
        }
    }
    findings
}

const HIGH_ENTROPY_STRING_RATIO: f64 = 0.85;

pub fn high_entropy_strings(strings: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut found: HashSet<String> = HashSet::new();

    for s in strings {
        if s.len() < 32 {
            continue;
        }
        if is_base64(s) || is_hex(s) {
            continue;
        }

        let entropy = calculate_entropy(s.as_bytes());
        let max_entropy = max_entropy_for_length(s.len());
        if max_entropy <= 0.0 {
            continue;
        }

        let ratio = entropy / max_entropy;
        if ratio < HIGH_ENTROPY_STRING_RATIO {
            continue;
        }

        if !found.insert(s.clone()) {
            continue;
        }

        let severity = if ratio >= 0.92 {
            Severity::High
        } else {
            Severity::Medium
        };

        findings.push(Finding {
            severity,
            title: "High Entropy String".to_string(),
            category: "Encoded String".to_string(),
            description: format!(
                "String has high entropy ({:.2} bits, {:.0}% of max): {}",
                entropy,
                ratio * 100.0,
                s
            ),
        });
    }
    findings
}

pub fn high_entropy_sections(sections: &[Section], ) -> Vec<Finding> {
    let mut findings = Vec::new();

    for section in sections {
        if section.bytes.len() < MIN_ENTROPY_SECTION_SIZE {
            continue;
        }

        let entropy = calculate_entropy(&section.bytes);
        if !is_entropy_suspicious(&section.name, entropy) {
            continue;
        }

        let expected = max_expected_entropy_for(&section.name);
        let delta = entropy - expected;

        let severity = if entropy >= 7.60 {
            Severity::High
        } else if entropy >= 7.0 {
            Severity::Medium
        } else {
            Severity::Low
        };

        findings.push(Finding {
            severity,
            title: "High Entropy Section".to_string(),
            category: "Entropy".to_string(),
            description: format!(
                "Section '{}' has entropy {:.2} (expected <= {:.2}, delta {:.2})",
                section.name,
                entropy,
                expected,
                delta,
            ),
        });
    }
    findings
}

pub fn detect_packed_binary(sections: &[Section]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut score: i32 = 0;
    let mut high_entropy_sections = 0;
    let mut suspicious_sections = 0;
    let mut packer_named_sections = 0;

    for section in sections {
        if section.bytes.len() < MIN_ENTROPY_SECTION_SIZE {
            continue;
        }

        let entropy = calculate_entropy(&section.bytes);
        let expected = max_expected_entropy_for(&section.name);
        let delta = entropy - expected;

        let known_packer_name = is_known_packer_section(&section.name);
        let entropy_above_baseline = delta > 0.75;
        let very_high_entropy = entropy >= 7.5;

        if known_packer_name {
            score += 5;
            packer_named_sections += 1;
        }
        if entropy_above_baseline {
            score += 2;
            suspicious_sections += 1;
        }
        if very_high_entropy {
            score += 2;
            high_entropy_sections += 1;
        }
        if delta > 1.5 {
            score += 2;
        }
        if delta > 2.0 {
            score += 1;
        }
    }

    if high_entropy_sections >= 2 {
        score += 2;
    }
    if suspicious_sections >= 2 {
        score += 1;
    }
    if packer_named_sections >= 1 && high_entropy_sections >= 1 {
        score += 2;
    }

    let severity = if score >= 12 {
        Some(Severity::High)
    } else if score >= 8 {
        Some(Severity::Medium)
    } else if score >= 5 {
        Some(Severity::Low)
    } else {
        None
    };

    if let Some(severity) = severity {
        findings.push(Finding {
            severity,
            title: "Likely Packed Binary".to_string(),
            category: "Packing".to_string(),
            description: format!(
                "Packing indicators detected (score {}, high-entropy sections: {}, baseline-violating sections: {}, packer-named sections: {})",
                score,
                high_entropy_sections,
                suspicious_sections,
                packer_named_sections
            ),
        });
    }
    findings
}