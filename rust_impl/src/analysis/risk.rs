use crate::models::{Finding, Severity, RiskSummary, RiskLevel};

fn severity_score(severity: &Severity) -> u8 {
    match severity {
        Severity::Low => 5,
        Severity::Medium => 10,
        Severity::High => 20,
        Severity::Critical => 30,
    }
}

fn risk_level(score: u8) -> RiskLevel {
    match score {
        0..=29 => RiskLevel::Low,
        30..=49 => RiskLevel::Medium,
        50..=139 => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

fn category_weight(category: &str) -> f64 {
    match category {
        "Packing" => 2.5,
        "Credential" => 2.0,
        "Suspicious Import" => 0.5,
        "Encoded String" => 0.75,
        "Entropy" => 1.5,
        "URL" => 1.25,
        "IP" => 1.25,
        _ => 1.0,
    }
}
pub fn calculate_risk_score(findings: &[Finding], ) -> RiskSummary {
    let mut score = 0;

    for finding in findings {
        score += severity_score(&finding.severity);
    }
    score = score.min(200);
    RiskSummary {
        score,
        level: risk_level(score),
        reason_count: findings.len(),
    }
}