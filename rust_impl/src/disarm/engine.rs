use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use capstone::InsnGroupType;
use capstone::arch::arm64::Arm64OperandType;
use capstone::arch::x86::X86OperandType;
use capstone::prelude::*;

use crate::models::{
    AddressKind, BinaryFormat, BinaryInfo, Disassembly, Instruction, Section, Symbol,
};

pub type SymbolLabels = BTreeMap<u64, Vec<String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisassemblyArchitecture {
    X86_64,
    AArch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisassemblyOptions {
    pub max_bytes: usize,
    pub max_instructions: usize,
}

impl Default for DisassemblyOptions {
    fn default() -> Self {
        Self {
            max_bytes: 4096,
            max_instructions: 200,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisassemblyError {
    UnsupportedArchitecture(String),
    MissingTextSection,
    MissingSymbol(String),
    InvalidRequest(String),
    AddressOutsideSections(u64),
    UnalignedAddress { address: u64, alignment: u64 },
    EmptyRange,
    NoInstructionsDecoded,
    Capstone(String),
}

impl fmt::Display for DisassemblyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArchitecture(architecture) => {
                write!(f, "unsupported disassembly architecture: {architecture}")
            }
            Self::MissingTextSection => {
                write!(f, "binary does not contain a non-empty .text section")
            }
            Self::MissingSymbol(symbol) => write!(f, "no symbol or export named '{symbol}'"),
            Self::InvalidRequest(message) => write!(f, "invalid disassembly request: {message}"),
            Self::AddressOutsideSections(address) => {
                write!(
                    f,
                    "address 0x{address:x} is outside all file-backed sections"
                )
            }
            Self::UnalignedAddress { address, alignment } => write!(
                f,
                "address 0x{address:x} is not aligned to {alignment} bytes"
            ),
            Self::EmptyRange => write!(f, "the requested disassembly range is empty"),
            Self::NoInstructionsDecoded => {
                write!(
                    f,
                    "Capstone could not decode an instruction in the requested range"
                )
            }
            Self::Capstone(error) => write!(f, "Capstone disassembly error: {error}"),
        }
    }
}

impl Error for DisassemblyError {}

pub fn architecture_for(architecture: &str) -> Result<DisassemblyArchitecture, DisassemblyError> {
    match architecture.trim().to_ascii_lowercase().as_str() {
        "62" | "x86_64" | "amd64" => Ok(DisassemblyArchitecture::X86_64),
        "183" | "aarch64" | "arm64" => Ok(DisassemblyArchitecture::AArch64),
        other => Err(DisassemblyError::UnsupportedArchitecture(other.to_string())),
    }
}

pub fn build_symbol_labels(symbols: &[Symbol], exports: &[Symbol]) -> SymbolLabels {
    let mut labels: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();

    for symbol in symbols.iter().chain(exports) {
        if symbol.address == 0 || symbol.name.is_empty() {
            continue;
        }
        labels
            .entry(symbol.address)
            .or_default()
            .insert(symbol.name.clone());
    }

    labels
        .into_iter()
        .map(|(address, names)| (address, names.into_iter().collect()))
        .collect()
}

pub fn symbol_address(labels: &SymbolLabels, name: &str) -> Option<u64> {
    labels.iter().find_map(|(address, names)| {
        names
            .iter()
            .any(|candidate| candidate == name)
            .then_some(*address)
    })
}

pub fn disassemble_text(
    info: &BinaryInfo,
    labels: &SymbolLabels,
    options: DisassemblyOptions,
) -> Result<Disassembly, DisassemblyError> {
    let text = text_section(info)?;
    disassemble_section_from(info, text, text.address, labels, options)
}

pub fn disassemble_from_entrypoint(
    info: &BinaryInfo,
    labels: &SymbolLabels,
    options: DisassemblyOptions,
) -> Result<Disassembly, DisassemblyError> {
    disassemble_at(info, info.entrypoint, labels, options)
}

pub fn disassemble_at(
    info: &BinaryInfo,
    address: u64,
    labels: &SymbolLabels,
    options: DisassemblyOptions,
) -> Result<Disassembly, DisassemblyError> {
    let section = section_containing(info, address)
        .ok_or(DisassemblyError::AddressOutsideSections(address))?;
    disassemble_section_from(info, section, address, labels, options)
}

fn text_section(info: &BinaryInfo) -> Result<&Section, DisassemblyError> {
    info.sections
        .iter()
        .find(|section| section.name == ".text" && !section.bytes.is_empty())
        .ok_or(DisassemblyError::MissingTextSection)
}

fn section_containing(info: &BinaryInfo, address: u64) -> Option<&Section> {
    info.sections.iter().find(|section| {
        let end = section.address.saturating_add(section.bytes.len() as u64);
        !section.bytes.is_empty() && address >= section.address && address < end
    })
}

fn disassemble_section_from(
    info: &BinaryInfo,
    section: &Section,
    address: u64,
    labels: &SymbolLabels,
    options: DisassemblyOptions,
) -> Result<Disassembly, DisassemblyError> {
    if options.max_bytes == 0 || options.max_instructions == 0 {
        return Err(DisassemblyError::EmptyRange);
    }

    let architecture = architecture_for(&info.architecture)?;
    if architecture == DisassemblyArchitecture::AArch64 && !address.is_multiple_of(4) {
        return Err(DisassemblyError::UnalignedAddress {
            address,
            alignment: 4,
        });
    }

    let section_end = section.address.saturating_add(section.bytes.len() as u64);
    if address < section.address || address >= section_end {
        return Err(DisassemblyError::AddressOutsideSections(address));
    }

    let offset = (address - section.address) as usize;
    let end = offset
        .saturating_add(options.max_bytes)
        .min(section.bytes.len());
    let input = &section.bytes[offset..end];
    if input.is_empty() {
        return Err(DisassemblyError::EmptyRange);
    }

    let capstone = capstone_for(architecture)?;
    let decoded = capstone
        .disasm_count(input, address, options.max_instructions)
        .map_err(|error| DisassemblyError::Capstone(error.to_string()))?;

    let instructions = decoded
        .iter()
        .map(|instruction| {
            let detail = capstone
                .insn_detail(instruction)
                .map_err(|error| DisassemblyError::Capstone(error.to_string()))?;
            let is_call = has_group(&detail, InsnGroupType::CS_GRP_CALL);
            let is_branch = has_group(&detail, InsnGroupType::CS_GRP_JUMP);
            let is_return = has_group(&detail, InsnGroupType::CS_GRP_RET);
            let branch_target = (is_call || is_branch)
                .then(|| direct_target(&detail, architecture))
                .flatten();

            Ok(Instruction {
                address: instruction.address(),
                bytes: instruction.bytes().to_vec(),
                mnemonic: instruction.mnemonic().unwrap_or_default().to_string(),
                operands: instruction.op_str().unwrap_or_default().to_string(),
                symbol_label: labels
                    .get(&instruction.address())
                    .map(|names| names.join(" | ")),
                branch_target,
                is_call,
                is_branch,
                is_return,
            })
        })
        .collect::<Result<Vec<_>, DisassemblyError>>()?;

    if instructions.is_empty() {
        return Err(DisassemblyError::NoInstructionsDecoded);
    }

    let decoded_byte_count = instructions
        .iter()
        .map(|instruction| instruction.bytes.len())
        .sum();

    Ok(Disassembly {
        section_name: section.name.clone(),
        address_kind: address_kind_for(info.format),
        start_address: address,
        input_byte_count: input.len(),
        decoded_byte_count,
        instructions,
    })
}

fn has_group(detail: &InsnDetail<'_>, group: InsnGroupType::Type) -> bool {
    detail
        .groups()
        .contains(&InsnGroupId(group as InsnGroupIdInt))
}

fn direct_target(detail: &InsnDetail<'_>, architecture: DisassemblyArchitecture) -> Option<u64> {
    let architecture_detail = detail.arch_detail();
    match architecture {
        DisassemblyArchitecture::X86_64 => architecture_detail.x86()?.operands().find_map(|op| {
            if let X86OperandType::Imm(value) = op.op_type {
                u64::try_from(value).ok()
            } else {
                None
            }
        }),
        DisassemblyArchitecture::AArch64 => {
            architecture_detail.arm64()?.operands().find_map(|op| {
                if let Arm64OperandType::Imm(value) = op.op_type {
                    u64::try_from(value).ok()
                } else {
                    None
                }
            })
        }
    }
}

fn address_kind_for(format: BinaryFormat) -> AddressKind {
    match format {
        BinaryFormat::Pe => AddressKind::RelativeVirtualAddress,
        BinaryFormat::Elf | BinaryFormat::MachO | BinaryFormat::Unknown => {
            AddressKind::VirtualAddress
        }
    }
}

fn capstone_for(architecture: DisassemblyArchitecture) -> Result<Capstone, DisassemblyError> {
    match architecture {
        DisassemblyArchitecture::X86_64 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|error| DisassemblyError::Capstone(error.to_string())),
        DisassemblyArchitecture::AArch64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .detail(true)
            .build()
            .map_err(|error| DisassemblyError::Capstone(error.to_string())),
    }
}
