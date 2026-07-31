use std::collections::{BTreeMap, BTreeSet};

use crate::data::explanation::explanation_for;
use crate::data::risk_signature::{MAX_RISK_SCORE, canonical_category_name, family_for_category};
use crate::models::{BinaryInfo, CodeFeatures, Disassembly, Finding, Instruction, RiskSummary};

const MAX_EVIDENCE_PER_CATEGORY: usize = 8;
const MAX_DESCRIPTION_CHARS: usize = 200;
const SUMMARY_CATEGORY_LIMIT: usize = 3;
const SUMMARY_SCORE_FLOOR: u32 = 5;
const APPENDIX_INSTRUCTION_LIMIT: usize = 40;

/// Facts about the analyzed file that `BinaryInfo` does not carry.
pub struct ReportInput<'a> {
    pub path: &'a str,
    pub file_size: u64,
    /// `None` when the format's symbol tables are not parsed, so the report can say "unknown"
    /// rather than claiming a binary is not stripped when nothing checked.
    pub is_stripped: Option<bool>,
}

/// Everything the bounded `.text` sweep produced. These three travel together because the
/// report cannot interpret the disassembly without knowing the budget it ran under: Capstone
/// stops at either the instruction budget or the first byte it cannot decode, and only one of
/// those two is a finding.
pub struct CodeScan<'a> {
    pub disassembly: &'a Disassembly,
    pub features: &'a CodeFeatures,
    pub instruction_budget: usize,
}

/// Render a Markdown report. Pure: same inputs always produce the same bytes.
pub fn render_report(
    input: &ReportInput<'_>,
    info: &BinaryInfo,
    findings: &[Finding],
    risk: &RiskSummary,
    code: Option<&CodeScan<'_>>,
) -> String {
    let groups = group_by_category(findings, risk);

    let mut report = String::new();
    write_header(&mut report, input, info);
    write_verdict(&mut report, risk, &groups);
    write_code_layer(&mut report, code);
    write_observations(&mut report, risk, &groups);
    write_next_steps(&mut report, input, &groups);
    write_limitations(&mut report);
    write_disassembly(&mut report, input, info, code);
    report
}

type CategoryGroup<'a> = (&'static str, Vec<&'a Finding>);

/// Group findings by canonical category, strongest contributor first.
fn group_by_category<'a>(findings: &'a [Finding], risk: &RiskSummary) -> Vec<CategoryGroup<'a>> {
    let mut grouped: BTreeMap<&'static str, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        grouped
            .entry(canonical_category_name(&finding.category))
            .or_default()
            .push(finding);
    }

    let mut groups: Vec<CategoryGroup<'a>> = grouped.into_iter().collect();
    groups.sort_by(|left, right| {
        category_score(risk, right.0)
            .cmp(&category_score(risk, left.0))
            .then_with(|| left.0.cmp(right.0))
    });
    groups
}

fn category_score(risk: &RiskSummary, category: &str) -> u32 {
    risk.category_scores.get(category).copied().unwrap_or(0)
}

fn write_header(report: &mut String, input: &ReportInput<'_>, info: &BinaryInfo) {
    report.push_str("# Binary analysis report\n\n");
    report.push_str(&format!("- **File:** `{}`\n", input.path));
    report.push_str(&format!("- **Size:** {} bytes\n", input.file_size));
    report.push_str(&format!("- **Format:** {:?}\n", info.format));
    report.push_str(&format!(
        "- **Architecture:** {}\n",
        architecture_name(&info.architecture)
    ));
    report.push_str(&format!("- **Entry point:** 0x{:x}\n", info.entrypoint));
    report.push_str(&format!("- **Sections:** {}\n", info.sections.len()));
    report.push_str(&format!(
        "- **Symbols stripped:** {}\n\n",
        stripped_label(input.is_stripped)
    ));
}

/// ELF stores the architecture as a raw `e_machine` number; name it for the reader without
/// losing the original value.
fn architecture_name(architecture: &str) -> String {
    match architecture {
        "3" => "i386 (ELF e_machine 3)".to_string(),
        "40" => "arm (ELF e_machine 40)".to_string(),
        "62" => "x86_64 (ELF e_machine 62)".to_string(),
        "183" => "aarch64 (ELF e_machine 183)".to_string(),
        other => other.to_string(),
    }
}

fn stripped_label(is_stripped: Option<bool>) -> &'static str {
    match is_stripped {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown — not checked for this format",
    }
}

fn write_verdict(report: &mut String, risk: &RiskSummary, groups: &[CategoryGroup<'_>]) {
    report.push_str("## Verdict\n\n");

    if groups.is_empty() {
        report.push_str(
            "No findings. Nothing in the strings, imports, sections or decoded instructions \
             matched a rule in the signature tables. This is not a clean bill of health: it \
             means the heuristics in this toolkit had nothing to say about the file.\n\n",
        );
        return;
    }

    report.push_str(&format!(
        "**Risk score {} of {} — {:?}.** {} across {}.\n\n",
        risk.score,
        MAX_RISK_SCORE,
        risk.level,
        plural(risk.reason_count, "finding"),
        plural(groups.len(), "category"),
    ));
    report.push_str(&summary_sentence(risk, groups));
    report.push_str(&corroboration_sentence(groups));
    report.push('\n');

    report.push_str("| Category | Score | Findings |\n| --- | ---: | ---: |\n");
    for (category, findings) in groups {
        report.push_str(&format!(
            "| {} | {} | {} |\n",
            category,
            category_score(risk, category),
            findings.len()
        ));
    }
    report.push('\n');
}

/// Compose the summary from the highest-scoring categories. Nothing is asserted here that the
/// findings do not already support.
fn summary_sentence(risk: &RiskSummary, groups: &[CategoryGroup<'_>]) -> String {
    let headlines: Vec<&str> = groups
        .iter()
        .filter(|(category, _)| category_score(risk, category) >= SUMMARY_SCORE_FLOOR)
        .take(SUMMARY_CATEGORY_LIMIT)
        .map(|(category, _)| headline_for(category))
        .collect();

    if headlines.is_empty() {
        return "Every category scored low on its own; the evidence below is weak individually \
                and should be read as context rather than as a conclusion.\n"
            .to_string();
    }
    format!(
        "The strongest evidence is {}.\n",
        join_phrases(&headlines)
    )
}

/// Weigh the evidence rather than counting it: findings spread across several behaviour families
/// are harder to explain as noise from one over-eager detector.
fn corroboration_sentence(groups: &[CategoryGroup<'_>]) -> String {
    let families: BTreeSet<&'static str> = groups
        .iter()
        .map(|(category, _)| family_for_category(category))
        .collect();
    let names: Vec<&str> = families.iter().copied().collect();

    if names.len() == 1 {
        return format!(
            "All of it sits in a single behaviour family ({}), so treat the score as weaker \
             than the number of findings suggests.\n",
            names[0]
        );
    }
    format!(
        "It spans {} behaviour families ({}), which is harder to explain as noise from one \
         over-eager detector.\n",
        names.len(),
        names.join(", ")
    )
}

fn headline_for(category: &str) -> &str {
    match explanation_for(category) {
        Some(explanation) => explanation.headline,
        None => category,
    }
}

fn write_code_layer(report: &mut String, code: Option<&CodeScan<'_>>) {
    report.push_str("## Code layer\n\n");

    let Some(code) = code else {
        report.push_str(
            "The code scan did not run: the architecture is unsupported, or no executable \
             section could be decoded. Everything below comes from the container, the extracted \
             strings and the import table only.\n\n",
        );
        return;
    };

    let disassembly = code.disassembly;
    report.push_str(&format!(
        "Capstone swept `{}` linearly from {} 0x{:x}, reading a window of {} bytes and decoding \
         {} of them ({}) into {} instructions.\n\n",
        disassembly.section_name,
        disassembly.address_kind.short_name(),
        disassembly.start_address,
        disassembly.input_byte_count,
        disassembly.decoded_byte_count,
        percentage(disassembly.decoded_byte_count, disassembly.input_byte_count),
        code.features.instruction_count,
    ));
    report.push_str(&coverage_sentence(code));
    report.push_str(&mix_sentence(code.features));
    report.push_str(&anti_analysis_sentence(code.features));
    report.push('\n');
}

/// The sweep can stop for two reasons, and only one of them is evidence. Say which happened
/// instead of leaving the reader to infer it from a percentage.
fn coverage_sentence(code: &CodeScan<'_>) -> String {
    let disassembly = code.disassembly;
    let undecoded = disassembly
        .input_byte_count
        .saturating_sub(disassembly.decoded_byte_count);

    if undecoded == 0 {
        return "The window decoded end to end, which is what an ordinary compiled binary looks \
                like.\n"
            .to_string();
    }
    if code.features.instruction_count >= code.instruction_budget {
        return format!(
            "The remaining {undecoded} bytes were not read because the sweep hit its \
             instruction budget, not because they failed to decode. Nothing should be inferred \
             from the shortfall.\n"
        );
    }
    format!(
        "The sweep then stopped with {undecoded} bytes left. A linear disassembler halts at the \
         first byte sequence it cannot read, so those bytes are either data placed inline among \
         the code, or a region that is not code yet — compressed or encrypted until the program \
         unpacks it at run time. Read this together with the entropy and packing categories.\n"
    )
}

/// Ratios rather than raw counts: a count of 900 calls means nothing without knowing whether
/// the sweep decoded three thousand instructions or three hundred thousand.
fn mix_sentence(features: &CodeFeatures) -> String {
    if features.instruction_count == 0 {
        return String::new();
    }
    format!(
        "Per hundred instructions the mix is {} calls, {} branches and {} returns.\n",
        per_hundred(features.call_count, features.instruction_count),
        per_hundred(features.branch_count, features.instruction_count),
        per_hundred(features.return_count, features.instruction_count),
    )
}

/// Instruction findings are deduplicated by title, so the evidence list understates how often a
/// pattern occurs. These totals are the honest numbers.
fn anti_analysis_sentence(features: &CodeFeatures) -> String {
    let counts = [
        (features.syscall_count, "direct syscall instructions"),
        (features.trap_count, "trap instructions"),
        (features.timing_instruction_count, "timing reads"),
        (
            features.anti_debug_pattern_count,
            "anti-debug instruction patterns",
        ),
    ];
    let present: Vec<String> = counts
        .iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, label)| format!("{count} {label}"))
        .collect();

    if present.is_empty() {
        return "No syscall, trap, timing or anti-debug instructions were decoded.\n".to_string();
    }
    let present: Vec<&str> = present.iter().map(String::as_str).collect();
    format!(
        "The sweep decoded {}. Instruction findings are deduplicated by title, so a pattern that \
         fires repeatedly still appears once in the evidence below; these are the full counts.\n",
        join_phrases(&present)
    )
}

fn percentage(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "0%".to_string();
    }
    format!("{}%", part.saturating_mul(100) / whole)
}

fn per_hundred(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "0".to_string();
    }
    format!("{:.1}", part as f64 * 100.0 / whole as f64)
}

fn write_observations(report: &mut String, risk: &RiskSummary, groups: &[CategoryGroup<'_>]) {
    if groups.is_empty() {
        return;
    }

    report.push_str("## Observations\n\n");
    for (category, findings) in groups {
        report.push_str(&format!(
            "### {} — {} points\n\n",
            category,
            category_score(risk, category)
        ));
        if let Some(explanation) = explanation_for(category) {
            report.push_str(&format!("{}\n\n", explanation.meaning));
            report.push_str(&format!("**Benign explanations.** {}\n\n", explanation.benign));
        }

        report.push_str(&format!("**Evidence ({}):**\n\n", plural(findings.len(), "finding")));
        for finding in findings.iter().take(MAX_EVIDENCE_PER_CATEGORY) {
            report.push_str(&format!(
                "- `[{:?}]` **{}** — {}\n",
                finding.severity,
                finding.title,
                condense(&finding.description)
            ));
        }
        if findings.len() > MAX_EVIDENCE_PER_CATEGORY {
            report.push_str(&format!(
                "- …and {} more\n",
                findings.len() - MAX_EVIDENCE_PER_CATEGORY
            ));
        }
        report.push('\n');
    }
}

fn write_next_steps(report: &mut String, input: &ReportInput<'_>, groups: &[CategoryGroup<'_>]) {
    let path = quote_path(input.path);
    let steps: Vec<(&str, String)> = groups
        .iter()
        .filter_map(|(category, _)| {
            explanation_for(category)
                .map(|explanation| (*category, explanation.next_step.replace("{binary}", &path)))
        })
        .collect();

    if steps.is_empty() {
        return;
    }

    report.push_str("## What to check next\n\n");
    for (category, step) in steps {
        report.push_str(&format!("**{category}.** {step}\n\n"));
    }
}

fn write_limitations(report: &mut String) {
    report.push_str(
        "## Limitations\n\n\
         This report is the output of a rule-based static analyzer, and every statement in it \
         is a description of the file rather than a judgement about intent. The binary is never \
         executed. Disassembly is a linear sweep over a bounded window of the executable \
         section, with no control-flow recovery, so indirect calls and jumps are left \
         unresolved. Packed or encrypted code is not unpacked, which means the string and \
         import evidence for such a file describes the loader and not the payload. Findings \
         come from signature tables and thresholds that are deliberately broad, so false \
         positives are expected and every finding above should be confirmed by hand before it \
         is acted on.\n",
    );
}

/// Show the code itself. A report that only names addresses asks the reader to go and run the
/// disassembler again; this saves them the round trip for the one window that always matters.
fn write_disassembly(
    report: &mut String,
    input: &ReportInput<'_>,
    info: &BinaryInfo,
    code: Option<&CodeScan<'_>>,
) {
    let Some(code) = code else {
        return;
    };
    let instructions = &code.disassembly.instructions;
    if instructions.is_empty() {
        return;
    }

    let start = entry_index(instructions, info.entrypoint);
    let window = &instructions[start..];
    let shown = window.len().min(APPENDIX_INSTRUCTION_LIMIT);

    report.push_str("\n## Appendix: decoded instructions\n\n");
    report.push_str(&format!(
        "The first {} instructions of `{}` from {} 0x{:x}{}. Branch targets resolve to a symbol \
         name where one is known and the target lands inside this window.\n\n",
        shown,
        code.disassembly.section_name,
        code.disassembly.address_kind.short_name(),
        window[0].address,
        if start > 0 { ", the entry point" } else { "" },
    ));

    let names = label_index(instructions);
    report.push_str("```\n");
    for instruction in window.iter().take(shown) {
        if let Some(label) = &instruction.symbol_label {
            report.push_str(&format!("{label}:\n"));
        }
        report.push_str(&format!(
            "  0x{:016x}  {:<24} {:<10} {}{}\n",
            instruction.address,
            hex_bytes(&instruction.bytes),
            instruction.mnemonic,
            instruction.operands,
            branch_annotation(instruction, &names),
        ));
    }
    report.push_str("```\n");

    if window.len() > shown {
        report.push_str(&format!(
            "\n{} further instructions were decoded but are not shown. For the full listing run \
             `cargo run -- {} --disasm text`.\n",
            window.len() - shown,
            quote_path(input.path),
        ));
    }
}

/// Prefer to start at the entry point: it is the one address in the file whose meaning is not
/// in doubt. Fall back to the start of the sweep when the entry point is elsewhere.
fn entry_index(instructions: &[Instruction], entrypoint: u64) -> usize {
    instructions
        .iter()
        .position(|instruction| instruction.address == entrypoint)
        .unwrap_or(0)
}

fn label_index(instructions: &[Instruction]) -> BTreeMap<u64, &str> {
    instructions
        .iter()
        .filter_map(|instruction| {
            instruction
                .symbol_label
                .as_deref()
                .map(|label| (instruction.address, label))
        })
        .collect()
}

fn branch_annotation(instruction: &Instruction, names: &BTreeMap<u64, &str>) -> String {
    match instruction.branch_target {
        None => String::new(),
        Some(address) => match names.get(&address) {
            Some(name) => format!("    ; -> {name}"),
            None => format!("    ; -> 0x{address:x}"),
        },
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join(" ")
}

/// Descriptions can be long and multi-line — some carry decoded payloads. Flatten and clip them
/// so one finding cannot swamp the report.
fn condense(description: &str) -> String {
    let collapsed = description.split_whitespace().collect::<Vec<&str>>().join(" ");
    if collapsed.chars().count() <= MAX_DESCRIPTION_CHARS {
        return collapsed;
    }
    let kept: String = collapsed.chars().take(MAX_DESCRIPTION_CHARS).collect();
    format!("{}…", kept.trim_end())
}

fn quote_path(path: &str) -> String {
    if path.contains(char::is_whitespace) {
        format!("\"{path}\"")
    } else {
        path.to_string()
    }
}

fn join_phrases(phrases: &[&str]) -> String {
    match phrases {
        [] => String::new(),
        [only] => (*only).to_string(),
        [rest @ .., last] => format!("{} and {}", rest.join(", "), last),
    }
}

fn plural(count: usize, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else if let Some(stem) = noun.strip_suffix('y') {
        format!("{count} {stem}ies")
    } else {
        format!("{count} {noun}s")
    }
}
