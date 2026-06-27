use std::collections::BTreeMap;

use crate::data::risk_signature::{
    canonical_category_name,
    rule_for_category,
    severity_multiplier,
    MAX_RISK_SCORE,
    LOW_RISK_MAX,
    MEDIUM_RISK_MAX,
    HIGH_RISK_MAX,
};
use crate::models::{Finding, Severity, RiskLevel, RiskSummary};

fn risk_level_for_score(score: u32) -> RiskLevel {
    match score {
        0..=LOW_RISK_MAX => RiskLevel::Low,
        20..=MEDIUM_RISK_MAX => RiskLevel::Medium,
        40..=HIGH_RISK_MAX => RiskLevel::High,
        _ => RiskLevel::Critical,
    }
}

pub fn calculate_risk_score(findings: &[Finding]) -> RiskSummary {
    if findings.is_empty() {
        return RiskSummary {
            score: 0,
            level: RiskLevel::Low,
            reason_count: 0,
        };
    }

    let mut grouped: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        let category = canonical_category_name(&finding.category).to_string();
        grouped.entry(category).or_default().push(finding);
    }

    let mut score: f64 = 0.0;
    let mut reason_count = 0;
    for (category, group) in grouped {
        reason_count += group.len();

        let rule = rule_for_category(&category);
        let mut category_score = rule.base_score as f64;

        let highest_severity = group
            .iter()
            .map(|f| &f.severity)
            .max_by_key(|s| match s {
                Severity::Low => 0,
                Severity::Medium => 1,
                Severity::High => 2,
                Severity::Critical => 3,
            })
            .unwrap_or(&Severity::Low);

        category_score *= severity_multiplier(highest_severity);
        if group.len() > 1 {
            category_score += (group.len() as f64 - 1.0) * rule.incremental_score as f64 * 0.5;
        }
        category_score *= rule.multiplier;
        score += category_score.min(rule.category_cap as f64);
    }

    let score = score.round() as u32.min(MAX_RISK_SCORE);
    let level = risk_level_for_score(score);

    RiskSummary {
        score,
        level,
        reason_count,
    }
}