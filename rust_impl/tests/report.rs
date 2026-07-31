use std::collections::BTreeMap;

use rust_impl::data::credential_signature::CREDENTIAL_RULES;
use rust_impl::data::explanation::{CATEGORY_EXPLANATIONS, explanation_for};
use rust_impl::data::import_signature::IMPORT_RULES;
use rust_impl::data::risk_signature::canonical_category_name;
use rust_impl::data::section_signature::SECTION_RULES;
use rust_impl::models::{
    AddressKind, BinaryFormat, BinaryInfo, CodeFeatures, Disassembly, Finding, Instruction,
    RiskLevel, RiskSummary, Section, Severity,
};
use rust_impl::report::{CodeScan, ReportInput, render_report};

/// Categories the analysis emits directly rather than through a signature table.
const HARD_CODED_CATEGORIES: &[&str] = &[
    "Networking",
    "Encoded String",
    "Entropy",
    "Packing",
    "Anti-Debugging",
    "Timing",
    "Environment Inspection",
];

fn info() -> BinaryInfo {
    BinaryInfo {
        format: BinaryFormat::Elf,
        architecture: "62".to_string(),
        entrypoint: 0x1040,
        sections: vec![Section {
            name: ".text".to_string(),
            address: 0x1000,
            size: 4,
            bytes: vec![0x90, 0x90, 0x90, 0xc3],
        }],
    }
}

fn input() -> ReportInput<'static> {
    ReportInput {
        path: "samples/hello",
        file_size: 16384,
        is_stripped: Some(false),
    }
}

fn finding(category: &str, title: &str, description: &str) -> Finding {
    Finding {
        severity: Severity::Medium,
        title: title.to_string(),
        category: category.to_string(),
        description: description.to_string(),
    }
}

fn instruction(address: u64, mnemonic: &str, operands: &str) -> Instruction {
    Instruction {
        address,
        bytes: vec![0x90],
        mnemonic: mnemonic.to_string(),
        operands: operands.to_string(),
        symbol_label: None,
        branch_target: None,
        is_call: false,
        is_branch: false,
        is_return: false,
    }
}

fn disassembly(decoded: usize, input: usize, instructions: Vec<Instruction>) -> Disassembly {
    Disassembly {
        section_name: ".text".to_string(),
        address_kind: AddressKind::VirtualAddress,
        start_address: 0x1000,
        input_byte_count: input,
        decoded_byte_count: decoded,
        instructions,
    }
}

fn summary(score: u32, findings: &[Finding], scores: &[(&str, u32)]) -> RiskSummary {
    let mut category_scores = BTreeMap::new();
    for (category, value) in scores {
        category_scores.insert((*category).to_string(), *value);
    }
    RiskSummary {
        score,
        level: RiskLevel::Medium,
        reason_count: findings.len(),
        category_scores,
    }
}

#[test]
fn every_emitted_category_has_an_explanation() {
    let emitted = IMPORT_RULES
        .iter()
        .map(|rule| rule.category)
        .chain(CREDENTIAL_RULES.iter().map(|rule| rule.category))
        .chain(SECTION_RULES.iter().map(|rule| rule.category))
        .chain(HARD_CODED_CATEGORIES.iter().copied());

    for category in emitted {
        assert!(
            explanation_for(category).is_some(),
            "no explanation covers findings in category {category}"
        );
    }
}

#[test]
fn explanations_use_canonical_category_names() {
    for entry in CATEGORY_EXPLANATIONS {
        assert_eq!(
            canonical_category_name(entry.category),
            entry.category,
            "{} is an alias, not a canonical category name",
            entry.category
        );
    }
}

#[test]
fn explanations_are_unique() {
    let mut seen: Vec<&str> = CATEGORY_EXPLANATIONS
        .iter()
        .map(|entry| entry.category)
        .collect();
    let total = seen.len();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), total, "duplicate category in CATEGORY_EXPLANATIONS");
}

#[test]
fn reports_no_findings_without_claiming_the_binary_is_clean() {
    let report = render_report(&input(), &info(), &[], &summary(0, &[], &[]), None);

    assert!(report.contains("No findings"));
    assert!(report.contains("not a clean bill of health"));
    assert!(report.contains("## Limitations"));
}

#[test]
fn orders_categories_by_contribution() {
    let findings = vec![
        finding("Networking", "Embedded URL", "http://example.com"),
        finding("Packing", "Likely Packed Binary", "Packing indicators detected"),
    ];
    let risk = summary(30, &findings, &[("Networking", 4), ("Packing", 25)]);
    let report = render_report(&input(), &info(), &findings, &risk, None);

    let packing = report.find("### Packing").expect("packing section");
    let networking = report.find("### Networking").expect("networking section");
    assert!(packing < networking, "higher-scoring category should come first");
    assert!(report.contains("The strongest evidence is packing."));
}

#[test]
fn explains_each_reported_category() {
    let findings = vec![finding(
        "Anti-Debugging",
        "Direct ptrace syscall pattern",
        "The previous instruction loads 0x65",
    )];
    let risk = summary(22, &findings, &[("Anti-Debugging", 22)]);
    let report = render_report(&input(), &info(), &findings, &risk, None);

    assert!(report.contains("PTRACE_TRACEME"));
    assert!(report.contains("**Benign explanations.**"));
    assert!(report.contains("## What to check next"));
}

#[test]
fn substitutes_the_analyzed_path_into_suggested_commands() {
    let findings = vec![finding("Anti-Debugging", "INT3 instruction", "int3 at 0x1041")];
    let risk = summary(22, &findings, &[("Anti-Debugging", 22)]);
    let report = render_report(&input(), &info(), &findings, &risk, None);

    assert!(!report.contains("{binary}"), "placeholder left in the report");
    assert!(report.contains("cargo run -- samples/hello --disasm address"));
}

#[test]
fn condenses_long_and_multi_line_descriptions() {
    let description = format!("first line\nsecond line {}", "x".repeat(500));
    let findings = vec![finding("Encoded String", "Base64 Encoded String", &description)];
    let risk = summary(8, &findings, &[("Encoded String", 8)]);
    let report = render_report(&input(), &info(), &findings, &risk, None);

    let evidence = report
        .lines()
        .find(|line| line.contains("Base64 Encoded String"))
        .expect("evidence line");
    assert!(evidence.chars().count() < 300, "evidence line was not clipped");
    assert!(evidence.ends_with('…'));
    assert!(!report.contains("second line\n"), "newlines were not collapsed");
}

#[test]
fn collapses_oversized_evidence_groups() {
    let findings: Vec<Finding> = (0..20)
        .map(|index| finding("Networking", "Embedded URL", &format!("http://example.com/{index}")))
        .collect();
    let risk = summary(12, &findings, &[("Networking", 12)]);
    let report = render_report(&input(), &info(), &findings, &risk, None);

    assert!(report.contains("**Evidence (20 findings):**"));
    assert!(report.contains("…and 12 more"));
}

#[test]
fn reports_a_skipped_code_scan_without_inventing_counts() {
    let findings = vec![finding("Networking", "Embedded URL", "http://example.com")];
    let risk = summary(4, &findings, &[("Networking", 4)]);

    let skipped = render_report(&input(), &info(), &findings, &risk, None);
    assert!(skipped.contains("The code scan did not run"));
    assert!(!skipped.contains("Capstone swept"));
    assert!(!skipped.contains("Appendix"));

    let features = CodeFeatures {
        instruction_count: 200,
        call_count: 30,
        branch_count: 50,
        return_count: 10,
        ..CodeFeatures::default()
    };
    let listing = disassembly(600, 600, vec![instruction(0x1000, "nop", "")]);
    let code = CodeScan {
        disassembly: &listing,
        features: &features,
        instruction_budget: 100_000,
    };
    let scanned = render_report(&input(), &info(), &findings, &risk, Some(&code));

    assert!(scanned.contains("decoding 600 of them (100%) into 200 instructions"));
    assert!(scanned.contains("15.0 calls, 25.0 branches and 5.0 returns"));
    assert!(scanned.contains("No syscall, trap, timing or anti-debug instructions were decoded"));
}

#[test]
fn separates_a_budget_stop_from_an_undecodable_byte() {
    let listing = disassembly(400, 1000, vec![instruction(0x1000, "nop", "")]);

    // Short of the budget: the sweep stopped because a byte would not decode.
    let features = CodeFeatures {
        instruction_count: 200,
        ..CodeFeatures::default()
    };
    let code = CodeScan {
        disassembly: &listing,
        features: &features,
        instruction_budget: 100_000,
    };
    let report = render_report(&input(), &info(), &[], &summary(0, &[], &[]), Some(&code));
    assert!(report.contains("stopped with 600 bytes left"));
    assert!(report.contains("compressed or encrypted"));

    // At the budget: the same shortfall means nothing.
    let features = CodeFeatures {
        instruction_count: 200,
        ..CodeFeatures::default()
    };
    let code = CodeScan {
        disassembly: &listing,
        features: &features,
        instruction_budget: 200,
    };
    let report = render_report(&input(), &info(), &[], &summary(0, &[], &[]), Some(&code));
    assert!(report.contains("hit its instruction budget"));
    assert!(!report.contains("compressed or encrypted"));
}

#[test]
fn gives_the_full_count_behind_a_deduplicated_finding() {
    let findings = vec![finding("Anti-Debugging", "INT3 instruction", "int3 at 0x1041")];
    let risk = summary(22, &findings, &[("Anti-Debugging", 22)]);
    let features = CodeFeatures {
        instruction_count: 200,
        trap_count: 17,
        timing_instruction_count: 3,
        ..CodeFeatures::default()
    };
    let listing = disassembly(600, 600, vec![instruction(0x1000, "nop", "")]);
    let code = CodeScan {
        disassembly: &listing,
        features: &features,
        instruction_budget: 100_000,
    };
    let report = render_report(&input(), &info(), &findings, &risk, Some(&code));

    assert!(report.contains("17 trap instructions and 3 timing reads"));
    assert!(report.contains("deduplicated by title"));
}

#[test]
fn lists_decoded_instructions_starting_at_the_entry_point() {
    let mut labelled = instruction(0x1040, "push", "rbp");
    labelled.symbol_label = Some("main".to_string());
    let mut jump = instruction(0x1044, "jmp", "0x1040");
    jump.branch_target = Some(0x1040);
    jump.is_branch = true;

    let listing = disassembly(
        3,
        3,
        vec![instruction(0x1000, "nop", ""), labelled, jump],
    );
    let features = CodeFeatures {
        instruction_count: 3,
        branch_count: 1,
        ..CodeFeatures::default()
    };
    let code = CodeScan {
        disassembly: &listing,
        features: &features,
        instruction_budget: 100_000,
    };
    let report = render_report(&input(), &info(), &[], &summary(0, &[], &[]), Some(&code));

    // info() puts the entry point at 0x1040, so the 0x1000 instruction is skipped.
    assert!(report.contains("## Appendix: decoded instructions"));
    assert!(report.contains("The first 2 instructions of `.text` from va 0x1040, the entry point"));
    assert!(!report.contains("0x0000000000001000"));
    assert!(report.contains("main:"));
    assert!(report.contains("; -> main"), "branch target was not resolved");
}

#[test]
fn names_the_architecture_and_reports_unknown_stripping_honestly() {
    let report = render_report(&input(), &info(), &[], &summary(0, &[], &[]), None);
    assert!(report.contains("x86_64 (ELF e_machine 62)"));
    assert!(report.contains("**Symbols stripped:** no"));

    let unchecked = ReportInput {
        path: "samples/app.exe",
        file_size: 4096,
        is_stripped: None,
    };
    let report = render_report(&unchecked, &info(), &[], &summary(0, &[], &[]), None);
    assert!(report.contains("unknown — not checked for this format"));
}

#[test]
fn weighs_evidence_by_how_many_behaviour_families_agree() {
    let single = vec![
        finding("Encoded String", "Base64 Encoded String", "aGVsbG8="),
        finding("Entropy", "High Entropy Section", "entropy 7.71"),
    ];
    let risk = summary(20, &single, &[("Encoded String", 8), ("Entropy", 12)]);
    let report = render_report(&input(), &info(), &single, &risk, None);
    assert!(report.contains("single behaviour family (Obfuscation)"));

    let mixed = vec![
        finding("Entropy", "High Entropy Section", "entropy 7.71"),
        finding("Anti-Debugging", "INT3 instruction", "int3 at 0x1041"),
    ];
    let risk = summary(34, &mixed, &[("Entropy", 12), ("Anti-Debugging", 22)]);
    let report = render_report(&input(), &info(), &mixed, &risk, None);
    assert!(report.contains("spans 2 behaviour families"));
}

#[test]
fn renders_the_same_bytes_for_the_same_input() {
    let findings = vec![
        finding("Packing", "Likely Packed Binary", "Packing indicators detected"),
        finding("Networking", "Embedded URL", "http://example.com"),
    ];
    let risk = summary(29, &findings, &[("Packing", 25), ("Networking", 4)]);

    let first = render_report(&input(), &info(), &findings, &risk, None);
    let second = render_report(&input(), &info(), &findings, &risk, None);
    assert_eq!(first, second);
}
