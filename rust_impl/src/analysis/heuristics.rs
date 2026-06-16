use crate::models::Finding;
use crate::models::Import;
use crate::data::import_signature::IMPORT_RULES;

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