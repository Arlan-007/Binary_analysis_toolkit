use std::collections::BTreeMap;
use std::collections::HashSet;

use crate::data::risk_signature::{
    canonical_category_name,
    family_for_category,
    family_rule_for,
    rule_for_category,
    severity_multiplier,
    MAX_RISK_SCORE,
    LOW_RISK_MAX,
    MEDIUM_RISK_MAX,
    HIGH_RISK_MAX,
    RISK_CATEGORY_SYNERGY_RULES,
    RISK_FAMILY_SYNERGY_RULES,
};
use crate::models::{Finding, Severity, RiskLevel, RiskSummary};

fn risk_level_for_score(score: u32) -> RiskLevel {
    if score <= LOW_RISK_MAX {
        RiskLevel::Low
    } else if score <= MEDIUM_RISK_MAX {
        RiskLevel::Medium
    } else if score <= HIGH_RISK_MAX {
        RiskLevel::High
    } else {
        RiskLevel::Critical
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

    // Pass 1: compute per-category scores.
    let mut grouped: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        let category = canonical_category_name(&finding.category).to_string();
        grouped.entry(category).or_default().push(finding);
    }

    let mut category_scores: BTreeMap<String, u32> = BTreeMap::new();
    for (category, group) in &grouped {
        let rule = rule_for_category(category);

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

        category_scores.insert(category.clone(), capped_score);
    }

    // Pass 2: category-pair synergy bonuses.
    let active_categories: HashSet<String> = category_scores.keys().map(|s| s.to_ascii_lowercase()).collect();
    for rule in RISK_CATEGORY_SYNERGY_RULES {
        let has_a = active_categories.iter().any(|c| c.eq_ignore_ascii_case(rule.category_a));
        let has_b = active_categories.iter().any(|c| c.eq_ignore_ascii_case(rule.category_b));
        if has_a && has_b {
            let score_a = category_scores.get(rule.category_a).copied().unwrap_or(0);
            let score_b = category_scores.get(rule.category_b).copied().unwrap_or(0);
            let target = if score_a >= score_b { rule.category_a } else { rule.category_b };
            if let Some(entry) = category_scores.get_mut(target) {
                let cat_rule = rule_for_category(target);
                *entry = (*entry + rule.bonus).min(rule.bonus_cap).min(cat_rule.category_cap);
            }
        }
    }

    // Pass 3: group by family, apply family caps.
    let mut family_totals: BTreeMap<&str, u32> = BTreeMap::new();
    for (category, &score) in &category_scores {
        let family = family_for_category(category);
        *family_totals.entry(family).or_default() += score;
    }

    let mut total_score: u32 = family_totals
        .iter()
        .map(|(&family, &score)| score.min(family_rule_for(family).family_cap))
        .sum();

    // Pass 4: family-pair synergy bonuses applied to the capped total.
    let active_families: Vec<&str> = family_totals.keys().copied().collect();
    for rule in RISK_FAMILY_SYNERGY_RULES {
        let has_a = active_families.iter().any(|f| f.eq_ignore_ascii_case(rule.family_a));
        let has_b = active_families.iter().any(|f| f.eq_ignore_ascii_case(rule.family_b));
        if has_a && has_b {
            total_score = total_score.saturating_add(rule.bonus).min(total_score + rule.bonus_cap);
        }
    }

    let total_score = total_score.min(MAX_RISK_SCORE);

    RiskSummary {
        score: total_score,
        level: risk_level_for_score(total_score),
        reason_count: findings.len(),
        category_scores,
    }
}