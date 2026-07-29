use rust_impl::disarm::{
    DisassemblyArchitecture, DisassemblyError, DisassemblyOptions, analyze_instructions,
    architecture_for, build_symbol_labels, disassemble_at, disassemble_from_entrypoint,
    disassemble_text, extract_code_features,
};
use rust_impl::models::{BinaryFormat, BinaryInfo, Section, Severity, Symbol, SymbolKind};

fn section(name: &str, address: u64, bytes: Vec<u8>) -> Section {
    Section {
        name: name.to_string(),
        address,
        size: bytes.len() as u64,
        bytes,
    }
}

fn info(format: BinaryFormat, architecture: &str, sections: Vec<Section>) -> BinaryInfo {
    BinaryInfo {
        format,
        architecture: architecture.to_string(),
        entrypoint: 0x1000,
        sections,
    }
}

fn text_info(format: BinaryFormat, architecture: &str, bytes: Vec<u8>) -> BinaryInfo {
    info(format, architecture, vec![section(".text", 0x1000, bytes)])
}

fn options() -> DisassemblyOptions {
    DisassemblyOptions {
        max_bytes: 64,
        max_instructions: 16,
    }
}

#[test]
fn maps_supported_architectures() {
    assert_eq!(architecture_for("62"), Ok(DisassemblyArchitecture::X86_64));
    assert_eq!(
        architecture_for("x86_64"),
        Ok(DisassemblyArchitecture::X86_64)
    );
    assert_eq!(
        architecture_for("183"),
        Ok(DisassemblyArchitecture::AArch64)
    );
    assert_eq!(
        architecture_for("arm64"),
        Ok(DisassemblyArchitecture::AArch64)
    );
}

#[test]
fn rejects_unknown_architecture() {
    assert_eq!(
        architecture_for("40"),
        Err(DisassemblyError::UnsupportedArchitecture("40".to_string()))
    );
}

#[test]
fn decodes_x86_64_and_attaches_labels() {
    let binary = text_info(BinaryFormat::Elf, "62", vec![0x90, 0x0f, 0x31, 0xc3]);
    let symbols = vec![Symbol {
        name: "timing_probe".to_string(),
        address: 0x1001,
        kind: SymbolKind::Function,
    }];
    let labels = build_symbol_labels(&symbols, &[]);

    let decoded = disassemble_text(&binary, &labels, options()).unwrap();
    assert_eq!(decoded.instructions[0].mnemonic, "nop");
    assert_eq!(decoded.instructions[1].mnemonic, "rdtsc");
    assert_eq!(
        decoded.instructions[1].symbol_label.as_deref(),
        Some("timing_probe")
    );

    let findings = analyze_instructions(binary.format, &binary.architecture, &decoded.instructions);
    assert!(findings.iter().any(|finding| finding.category == "Timing"));
}

#[test]
fn decodes_aarch64() {
    // nop; svc #0; ret, encoded little-endian as stored in an ELF section.
    let binary = text_info(
        BinaryFormat::Elf,
        "183",
        vec![
            0x1f, 0x20, 0x03, 0xd5, 0x01, 0x00, 0x00, 0xd4, 0xc0, 0x03, 0x5f, 0xd6,
        ],
    );
    let decoded = disassemble_text(&binary, &Default::default(), options()).unwrap();
    assert_eq!(decoded.instructions[0].mnemonic, "nop");
    assert!(
        decoded
            .instructions
            .iter()
            .any(|instruction| instruction.mnemonic == "svc")
    );
}

#[test]
fn decodes_address_in_custom_section() {
    let binary = info(
        BinaryFormat::Elf,
        "62",
        vec![section(".packed", 0x2000, vec![0x90, 0xc3])],
    );
    let decoded = disassemble_at(&binary, 0x2000, &Default::default(), options()).unwrap();
    assert_eq!(decoded.section_name, ".packed");
    assert_eq!(decoded.instructions[0].mnemonic, "nop");
}

#[test]
fn decodes_entrypoint_in_custom_section() {
    let mut binary = info(
        BinaryFormat::Elf,
        "62",
        vec![section(".entry", 0x3000, vec![0x90, 0xc3])],
    );
    binary.entrypoint = 0x3000;
    let decoded = disassemble_from_entrypoint(&binary, &Default::default(), options()).unwrap();
    assert_eq!(decoded.section_name, ".entry");
}

#[test]
fn rejects_address_outside_sections() {
    let binary = text_info(BinaryFormat::Elf, "62", vec![0x90]);
    assert_eq!(
        disassemble_at(&binary, 0x2000, &Default::default(), options()),
        Err(DisassemblyError::AddressOutsideSections(0x2000))
    );
}

#[test]
fn rejects_unaligned_aarch64_address() {
    let binary = text_info(BinaryFormat::Elf, "183", vec![0x1f, 0x20, 0x03, 0xd5]);
    assert_eq!(
        disassemble_at(&binary, 0x1001, &Default::default(), options()),
        Err(DisassemblyError::UnalignedAddress {
            address: 0x1001,
            alignment: 4,
        })
    );
}

#[test]
fn rejects_empty_decode_result() {
    let binary = text_info(BinaryFormat::Elf, "62", vec![0x0f]);
    assert_eq!(
        disassemble_text(&binary, &Default::default(), options()),
        Err(DisassemblyError::NoInstructionsDecoded)
    );
}

#[test]
fn extracts_direct_x86_call_target() {
    // call 0x1010 from 0x1000
    let binary = text_info(BinaryFormat::Elf, "62", vec![0xe8, 0x0b, 0x00, 0x00, 0x00]);
    let decoded = disassemble_text(&binary, &Default::default(), options()).unwrap();
    assert!(decoded.instructions[0].is_call);
    assert_eq!(decoded.instructions[0].branch_target, Some(0x1010));
}

#[test]
fn extracts_direct_aarch64_branch_target() {
    // b 0x1008 from 0x1000
    let binary = text_info(BinaryFormat::Elf, "183", vec![0x02, 0x00, 0x00, 0x14]);
    let decoded = disassemble_text(&binary, &Default::default(), options()).unwrap();
    assert!(decoded.instructions[0].is_branch);
    assert_eq!(decoded.instructions[0].branch_target, Some(0x1008));
}

#[test]
fn finds_x86_64_elf_ptrace_syscall_only() {
    // mov eax, 101; syscall
    let elf = text_info(
        BinaryFormat::Elf,
        "62",
        vec![0xb8, 0x65, 0x00, 0x00, 0x00, 0x0f, 0x05],
    );
    let decoded = disassemble_text(&elf, &Default::default(), options()).unwrap();
    let elf_findings = analyze_instructions(elf.format, &elf.architecture, &decoded.instructions);
    assert!(elf_findings.iter().any(|finding| {
        finding.title == "Direct ptrace syscall pattern" && finding.severity == Severity::Medium
    }));

    let pe_findings = analyze_instructions(BinaryFormat::Pe, "x86_64", &decoded.instructions);
    assert!(
        pe_findings
            .iter()
            .all(|finding| finding.title != "Direct ptrace syscall pattern")
    );
}

#[test]
fn finds_aarch64_elf_ptrace_syscall() {
    // mov x8, #117; svc #0
    let binary = text_info(
        BinaryFormat::Elf,
        "183",
        vec![0xa8, 0x0e, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4],
    );
    let decoded = disassemble_text(&binary, &Default::default(), options()).unwrap();
    let findings = analyze_instructions(binary.format, &binary.architecture, &decoded.instructions);
    assert!(findings.iter().any(|finding| {
        finding.title == "Direct ptrace syscall pattern" && finding.severity == Severity::Medium
    }));
}

#[test]
fn extracts_deterministic_code_features() {
    // call next; rdtsc; int3; ret
    let binary = text_info(
        BinaryFormat::Elf,
        "62",
        vec![0xe8, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x31, 0xcc, 0xc3],
    );
    let decoded = disassemble_text(&binary, &Default::default(), options()).unwrap();
    let findings = analyze_instructions(binary.format, &binary.architecture, &decoded.instructions);
    let features = extract_code_features(&decoded.instructions, &findings);

    assert_eq!(features.instruction_count, 4);
    assert_eq!(features.call_count, 1);
    assert_eq!(features.branch_count, 0);
    assert_eq!(features.return_count, 1);
    assert_eq!(features.trap_count, 1);
    assert_eq!(features.timing_instruction_count, 1);
    assert_eq!(features.anti_debug_pattern_count, 1);
}

#[test]
fn rejects_missing_text_section() {
    let binary = info(BinaryFormat::Elf, "62", vec![]);
    assert_eq!(
        disassemble_text(&binary, &Default::default(), options()),
        Err(DisassemblyError::MissingTextSection)
    );
}

#[test]
fn rejects_zero_limits() {
    let binary = text_info(BinaryFormat::Elf, "62", vec![0x90]);
    assert_eq!(
        disassemble_text(
            &binary,
            &Default::default(),
            DisassemblyOptions {
                max_bytes: 0,
                max_instructions: 1,
            },
        ),
        Err(DisassemblyError::EmptyRange)
    );
}
