use std::collections::BTreeSet;

use crate::models::{BinaryFormat, CodeFeatures, Finding, Instruction, Severity};

pub fn analyze_instructions(
    format: BinaryFormat,
    architecture: &str,
    instructions: &[Instruction],
) -> Vec<Finding> {
    let normalized = architecture.trim().to_ascii_lowercase();
    if matches!(normalized.as_str(), "62" | "x86_64" | "amd64") {
        return analyze_x86_64(format, instructions);
    }
    if matches!(normalized.as_str(), "183" | "aarch64" | "arm64") {
        return analyze_aarch64(format, instructions);
    }
    Vec::new()
}

pub fn extract_code_features(instructions: &[Instruction], findings: &[Finding]) -> CodeFeatures {
    CodeFeatures {
        instruction_count: instructions.len(),
        call_count: instructions
            .iter()
            .filter(|instruction| instruction.is_call)
            .count(),
        branch_count: instructions
            .iter()
            .filter(|instruction| instruction.is_branch)
            .count(),
        return_count: instructions
            .iter()
            .filter(|instruction| instruction.is_return)
            .count(),
        syscall_count: instructions
            .iter()
            .filter(|instruction| matches!(instruction.mnemonic.as_str(), "syscall" | "svc"))
            .count(),
        trap_count: instructions
            .iter()
            .filter(|instruction| matches!(instruction.mnemonic.as_str(), "int3" | "brk"))
            .count(),
        timing_instruction_count: instructions
            .iter()
            .filter(|instruction| is_timing_instruction(instruction))
            .count(),
        anti_debug_pattern_count: findings
            .iter()
            .filter(|finding| finding.category == "Anti-Debugging")
            .count(),
    }
}

fn analyze_x86_64(format: BinaryFormat, instructions: &[Instruction]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();

    for (index, instruction) in instructions.iter().enumerate() {
        match instruction.mnemonic.as_str() {
            "int3" => push_once(
                &mut findings,
                &mut seen,
                instruction,
                "x86 INT3 instruction",
                "Anti-Debugging",
                Severity::Low,
                "INT3 can implement a debugger trap, though it is also common padding.",
            ),
            "rdtsc" | "rdtscp" => push_once(
                &mut findings,
                &mut seen,
                instruction,
                "x86 timestamp-counter read",
                "Timing",
                Severity::Low,
                "A timestamp-counter read can support timing-based anti-analysis checks.",
            ),
            "cpuid" => push_once(
                &mut findings,
                &mut seen,
                instruction,
                "x86 CPUID environment query",
                "Environment Inspection",
                Severity::Low,
                "CPUID can inspect CPU or virtual-machine characteristics.",
            ),
            "syscall"
                if format == BinaryFormat::Elf
                    && previous_instruction_loads_x86_ptrace(instructions, index) =>
            {
                push_once(
                    &mut findings,
                    &mut seen,
                    instruction,
                    "Direct ptrace syscall pattern",
                    "Anti-Debugging",
                    Severity::Medium,
                    "The previous instruction loads Linux x86-64 ptrace syscall number 101.",
                )
            }
            _ => {}
        }
    }
    findings
}

fn analyze_aarch64(format: BinaryFormat, instructions: &[Instruction]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();

    for (index, instruction) in instructions.iter().enumerate() {
        match instruction.mnemonic.as_str() {
            "brk" => push_once(
                &mut findings,
                &mut seen,
                instruction,
                "AArch64 BRK instruction",
                "Anti-Debugging",
                Severity::Low,
                "BRK creates a trap; it can be anti-debugging but is also used for assertions.",
            ),
            "mrs" if looks_like_timing_register(&instruction.operands) => push_once(
                &mut findings,
                &mut seen,
                instruction,
                "AArch64 timing/system register read",
                "Timing",
                Severity::Low,
                "MRS reads a timing or system register that may support environment checks.",
            ),
            "svc"
                if format == BinaryFormat::Elf
                    && previous_instruction_loads_aarch64_ptrace(instructions, index) =>
            {
                push_once(
                    &mut findings,
                    &mut seen,
                    instruction,
                    "Direct ptrace syscall pattern",
                    "Anti-Debugging",
                    Severity::Medium,
                    "The previous instruction loads Linux AArch64 ptrace syscall number 117.",
                )
            }
            _ => {}
        }
    }
    findings
}

fn previous_instruction_loads_x86_ptrace(
    instructions: &[Instruction],
    syscall_index: usize,
) -> bool {
    let Some(previous) = syscall_index
        .checked_sub(1)
        .and_then(|index| instructions.get(index))
    else {
        return false;
    };

    if previous.mnemonic != "mov" {
        return false;
    }

    matches!(
        compact_operands(&previous.operands).as_str(),
        "eax,0x65" | "rax,0x65" | "eax,101" | "rax,101"
    )
}

fn previous_instruction_loads_aarch64_ptrace(
    instructions: &[Instruction],
    syscall_index: usize,
) -> bool {
    let Some(previous) = syscall_index
        .checked_sub(1)
        .and_then(|index| instructions.get(index))
    else {
        return false;
    };

    if previous.mnemonic != "mov" {
        return false;
    }

    matches!(
        compact_operands(&previous.operands).as_str(),
        "x8,#0x75" | "x8,#117"
    )
}

fn compact_operands(operands: &str) -> String {
    operands
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn looks_like_timing_register(operands: &str) -> bool {
    let operands = operands.to_ascii_lowercase();
    operands.contains("cntvct") || operands.contains("cntpct") || operands.contains("midr")
}

fn is_timing_instruction(instruction: &Instruction) -> bool {
    matches!(instruction.mnemonic.as_str(), "rdtsc" | "rdtscp")
        || (instruction.mnemonic == "mrs" && looks_like_timing_register(&instruction.operands))
}

fn push_once(
    findings: &mut Vec<Finding>,
    seen: &mut BTreeSet<String>,
    instruction: &Instruction,
    title: &str,
    category: &str,
    severity: Severity,
    explanation: &str,
) {
    if !seen.insert(title.to_string()) {
        return;
    }

    let label = instruction
        .symbol_label
        .as_deref()
        .map(|label| format!(" ({label})"))
        .unwrap_or_default();
    findings.push(Finding {
        severity,
        title: title.to_string(),
        category: category.to_string(),
        description: format!(
            "{explanation} Observed at 0x{:x}{label}: {} {}",
            instruction.address, instruction.mnemonic, instruction.operands
        ),
    });
}
