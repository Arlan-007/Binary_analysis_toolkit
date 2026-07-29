use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub architecture: String,
    pub entrypoint: u64,
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub library: String,
    pub function: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub category: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub struct RiskSummary {
    pub score: u32,
    pub level: RiskLevel,
    pub reason_count: usize,
    pub category_scores: BTreeMap<String, u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Object,
    Other,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub symbol_label: Option<String>,
    pub branch_target: Option<u64>,
    pub is_call: bool,
    pub is_branch: bool,
    pub is_return: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    VirtualAddress,
    RelativeVirtualAddress,
}

impl AddressKind {
    pub fn short_name(self) -> &'static str {
        match self {
            Self::VirtualAddress => "va",
            Self::RelativeVirtualAddress => "rva",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disassembly {
    pub section_name: String,
    pub address_kind: AddressKind,
    pub start_address: u64,
    pub input_byte_count: usize,
    pub decoded_byte_count: usize,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeFeatures {
    pub instruction_count: usize,
    pub call_count: usize,
    pub branch_count: usize,
    pub return_count: usize,
    pub syscall_count: usize,
    pub trap_count: usize,
    pub timing_instruction_count: usize,
    pub anti_debug_pattern_count: usize,
}
