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

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

pub fn calculate_risk_score(findings: &[Finding]) -> RiskSummary {
    if findings.is_empty() {
        return RiskSummary {
            score: 0,
            level: RiskLevel::Low,
            reason_count: 0,
            category_scores: BTreeMap::new(),
        };
    }

    let mut grouped: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        let category = canonical_category_name(&finding.category).to_string();
        grouped.entry(category).or_default().push(finding);
    }

    let mut total_score: f64 = 0.0;
    let mut category_scores: BTreeMap<String, u32> = BTreeMap::new();
    for (category, group) in grouped {
        let rule = rule_for_category(&category);

        let highest_severity = group
            .iter()
            .max_by_key(|f| severity_rank(&f.severity))
            .map(|f| &f.severity)
            .unwrap_or(&Severity::Low);

        let mut category_score = rule.base_score as f64;
        category_score *= severity_multiplier(highest_severity);
        if group.len() > 1 {
            let extra = (group.len() - 1) as f64;
            category_score += extra * (rule.incremental_score as f64) * 0.5;
        }

        category_score *= rule.multiplier;

        let capped_score = category_score.round() as u32;
        let capped_score = capped_score.min(rule.category_cap);

        category_scores.insert(category, capped_score);
        total_score += capped_score as f64;
    }

    let total_score = total_score.round() as u32;
    let total_score = total_score.min(MAX_RISK_SCORE);

    RiskSummary {
        score: total_score,
        level: risk_level_for_score(total_score),
        reason_count: findings.len(),
        category_scores,
    }
}