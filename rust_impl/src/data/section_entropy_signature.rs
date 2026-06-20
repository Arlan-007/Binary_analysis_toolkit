#[derive(Debug, Clone, Copy)]
pub struct SectionEntropyRule {
    pub pattern: &'static str,
    pub max_expected_entropy: f64,
    pub notes: &'static str,
}

pub const DEFAULT_MAX_EXPECTED_ENTROPY: f64 = 7.0;
pub const PACKED_BINARY_ENTROPY_THRESHOLD: f64 = 7.20;
pub const MIN_ENTROPY_SECTION_SIZE: usize = 512;

pub const SECTION_ENTROPY_RULES: &[SectionEntropyRule] = &[
    // ELF / PE code and data sections
    SectionEntropyRule {
        pattern: ".text",
        max_expected_entropy: 7.00,
        notes: "Executable code; moderate entropy is normal.",
    },
    SectionEntropyRule {
        pattern: ".rodata",
        max_expected_entropy: 6.20,
        notes: "Read-only constants and strings.",
    },
    SectionEntropyRule {
        pattern: ".rdata",
        max_expected_entropy: 6.20,
        notes: "Read-only data on PE binaries.",
    },
    SectionEntropyRule {
        pattern: ".data",
        max_expected_entropy: 5.80,
        notes: "Initialized writable data; usually lower entropy.",
    },
    SectionEntropyRule {
        pattern: ".bss",
        max_expected_entropy: 0.10,
        notes: "Uninitialized data; often empty in file bytes.",
    },

    // ELF loader / relocation / linkage sections
    SectionEntropyRule {
        pattern: ".interp",
        max_expected_entropy: 4.50,
        notes: "Interpreter path; should be low entropy.",
    },
    SectionEntropyRule {
        pattern: ".note.",
        max_expected_entropy: 5.00,
        notes: "ELF notes; short metadata blocks.",
    },
    SectionEntropyRule {
        pattern: ".note",
        max_expected_entropy: 5.00,
        notes: "ELF notes; short metadata blocks.",
    },
    SectionEntropyRule {
        pattern: ".hash",
        max_expected_entropy: 5.50,
        notes: "Legacy ELF hash table.",
    },
    SectionEntropyRule {
        pattern: ".gnu.hash",
        max_expected_entropy: 6.80,
        notes: "GNU hash table can be fairly dense.",
    },
    SectionEntropyRule {
        pattern: ".dynsym",
        max_expected_entropy: 5.50,
        notes: "Dynamic symbol table.",
    },
    SectionEntropyRule {
        pattern: ".dynstr",
        max_expected_entropy: 6.20,
        notes: "Dynamic string table.",
    },
    SectionEntropyRule {
        pattern: ".symtab",
        max_expected_entropy: 5.50,
        notes: "Full symbol table.",
    },
    SectionEntropyRule {
        pattern: ".strtab",
        max_expected_entropy: 6.20,
        notes: "String table.",
    },
    SectionEntropyRule {
        pattern: ".gnu.version",
        max_expected_entropy: 4.00,
        notes: "Versioning metadata.",
    },
    SectionEntropyRule {
        pattern: ".gnu.version_r",
        max_expected_entropy: 4.50,
        notes: "Version requirements metadata.",
    },
    SectionEntropyRule {
        pattern: ".rela.dyn",
        max_expected_entropy: 4.50,
        notes: "Relocation entries.",
    },
    SectionEntropyRule {
        pattern: ".rela.plt",
        max_expected_entropy: 4.50,
        notes: "PLT relocation entries.",
    },
    SectionEntropyRule {
        pattern: ".rel.dyn",
        max_expected_entropy: 4.50,
        notes: "Relocation entries.",
    },
    SectionEntropyRule {
        pattern: ".rel.plt",
        max_expected_entropy: 4.50,
        notes: "PLT relocation entries.",
    },
    SectionEntropyRule {
        pattern: ".init",
        max_expected_entropy: 5.50,
        notes: "Initialization code.",
    },
    SectionEntropyRule {
        pattern: ".fini",
        max_expected_entropy: 5.50,
        notes: "Finalization code.",
    },
    SectionEntropyRule {
        pattern: ".plt",
        max_expected_entropy: 6.00,
        notes: "Procedure linkage table.",
    },
    SectionEntropyRule {
        pattern: ".plt.got",
        max_expected_entropy: 6.00,
        notes: "PLT/GOT linkage stub.",
    },
    SectionEntropyRule {
        pattern: ".plt.sec",
        max_expected_entropy: 6.00,
        notes: "PLT section variant.",
    },
    SectionEntropyRule {
        pattern: ".got",
        max_expected_entropy: 4.00,
        notes: "Global offset table.",
    },
    SectionEntropyRule {
        pattern: ".got.plt",
        max_expected_entropy: 4.50,
        notes: "GOT entries for PLT.",
    },
    SectionEntropyRule {
        pattern: ".dynamic",
        max_expected_entropy: 4.50,
        notes: "Dynamic linking metadata.",
    },
    SectionEntropyRule {
        pattern: ".eh_frame",
        max_expected_entropy: 6.00,
        notes: "Exception handling frames.",
    },
    SectionEntropyRule {
        pattern: ".eh_frame_hdr",
        max_expected_entropy: 5.50,
        notes: "EH frame header.",
    },
    SectionEntropyRule {
        pattern: ".gcc_except_table",
        max_expected_entropy: 5.80,
        notes: "Exception tables.",
    },
    SectionEntropyRule {
        pattern: ".init_array",
        max_expected_entropy: 4.50,
        notes: "Constructor pointers.",
    },
    SectionEntropyRule {
        pattern: ".fini_array",
        max_expected_entropy: 4.50,
        notes: "Destructor pointers.",
    },
    SectionEntropyRule {
        pattern: ".preinit_array",
        max_expected_entropy: 4.50,
        notes: "Pre-init constructor pointers.",
    },
    SectionEntropyRule {
        pattern: ".ctors",
        max_expected_entropy: 4.50,
        notes: "Constructor list.",
    },
    SectionEntropyRule {
        pattern: ".dtors",
        max_expected_entropy: 4.50,
        notes: "Destructor list.",
    },
    SectionEntropyRule {
        pattern: ".jcr",
        max_expected_entropy: 2.00,
        notes: "Legacy Java registration data; usually tiny.",
    },
    SectionEntropyRule {
        pattern: ".tdata",
        max_expected_entropy: 5.50,
        notes: "Thread-local initialized data.",
    },
    SectionEntropyRule {
        pattern: ".tbss",
        max_expected_entropy: 0.10,
        notes: "Thread-local uninitialized data.",
    },
    SectionEntropyRule {
        pattern: ".tls",
        max_expected_entropy: 4.50,
        notes: "Thread-local storage section.",
    },
    SectionEntropyRule {
        pattern: ".comment",
        max_expected_entropy: 5.50,
        notes: "Build/toolchain metadata.",
    },
    SectionEntropyRule {
        pattern: ".shstrtab",
        max_expected_entropy: 5.50,
        notes: "ELF section name string table.",
    },

    // PE-specific metadata / tables
    SectionEntropyRule {
        pattern: ".edata",
        max_expected_entropy: 5.00,
        notes: "Export directory.",
    },
    SectionEntropyRule {
        pattern: ".idata",
        max_expected_entropy: 5.50,
        notes: "Import directory.",
    },
    SectionEntropyRule {
        pattern: ".didat",
        max_expected_entropy: 5.50,
        notes: "Delay-load import data.",
    },
    SectionEntropyRule {
        pattern: ".reloc",
        max_expected_entropy: 4.50,
        notes: "Relocation table.",
    },
    SectionEntropyRule {
        pattern: ".rsrc",
        max_expected_entropy: 6.50,
        notes: "Resource section; can legitimately be denser.",
    },
    SectionEntropyRule {
        pattern: ".pdata",
        max_expected_entropy: 5.50,
        notes: "Exception/unwind metadata.",
    },
    SectionEntropyRule {
        pattern: ".xdata",
        max_expected_entropy: 5.50,
        notes: "Exception/unwind metadata.",
    },
    SectionEntropyRule {
        pattern: ".tls",
        max_expected_entropy: 4.50,
        notes: "Thread-local storage.",
    },
    SectionEntropyRule {
        pattern: ".CRT",
        max_expected_entropy: 4.50,
        notes: "CRT initialization data.",
    },
    SectionEntropyRule {
        pattern: ".00cfg",
        max_expected_entropy: 4.50,
        notes: "CFG metadata.",
    },
    SectionEntropyRule {
        pattern: ".gfids",
        max_expected_entropy: 4.50,
        notes: "Guard function ID table.",
    },
    SectionEntropyRule {
        pattern: ".giats",
        max_expected_entropy: 4.50,
        notes: "Guard IAT table.",
    },
    SectionEntropyRule {
        pattern: ".mrdata",
        max_expected_entropy: 5.00,
        notes: "Read-only metadata/data.",
    },
    SectionEntropyRule {
        pattern: ".sdata",
        max_expected_entropy: 5.50,
        notes: "Small initialized data.",
    },
    SectionEntropyRule {
        pattern: ".bss",
        max_expected_entropy: 0.10,
        notes: "Uninitialized data.",
    },

    // Debug / symbol / metadata sections
    SectionEntropyRule {
        pattern: ".debug_",
        max_expected_entropy: 6.50,
        notes: "Debug data may be more varied than normal metadata.",
    },
    SectionEntropyRule {
        pattern: ".pdb",
        max_expected_entropy: 6.50,
        notes: "Debug-related data.",
    },
];

pub const PACKER_SECTION_NAMES: &[&str] = &[
    ".upx0",
    ".upx1",
    ".upx2",
    ".aspack",
    ".mpress",
    ".mpress1",
    ".petite",
    ".fsg",
    ".mew",
    ".kkrunchy",
    ".telock",
    ".tElock",
    ".vmp0",
    ".vmp1",
    ".themida",
    ".themida1",
    ".pebundle",
    ".pec",
    ".packed",
    ".pack",
    ".stub",
    ".crypt",
    ".cryptext",
    ".nsp1",
    ".nsp0",
    ".boom",
    ".yoda",
    ".svkp",
    ".lame",
    ".shrunk",
    ".sgn",
    ".enigma",
];

pub fn matches_pattern(section_name: &str, pattern: &str) -> bool {
    section_name == pattern || section_name.starts_with(pattern)
}

pub fn rule_for_section(section_name: &str) -> Option<&'static SectionEntropyRule> {
    SECTION_ENTROPY_RULES
        .iter()
        .find(|rule| matches_pattern(section_name, rule.pattern))
}

pub fn max_expected_entropy_for(section_name: &str) -> f64 {
    rule_for_section(section_name)
        .map(|rule| rule.max_expected_entropy)
        .unwrap_or(DEFAULT_MAX_EXPECTED_ENTROPY)
}

pub fn notes_for(section_name: &str) -> Option<&'static str> {
    rule_for_section(section_name).map(|rule| rule.notes)
}

pub fn is_known_packer_section(section_name: &str) -> bool {
    PACKER_SECTION_NAMES
        .iter()
        .any(|name| matches_pattern(section_name, name))
}

pub fn is_entropy_suspicious(section_name: &str, entropy: f64) -> bool {
    entropy > max_expected_entropy_for(section_name)
}

pub fn is_likely_packed_section(section_name: &str, entropy: f64) -> bool {
    is_known_packer_section(section_name) || entropy >= PACKED_BINARY_ENTROPY_THRESHOLD
}