use crate::models::Severity;

#[derive(Debug)]
pub struct SectionRule {
    pub names: &'static [&'static str],
    pub severity: Severity,
    pub category: &'static str,
    pub description: &'static str,
}

pub const SECTION_RULES: &[SectionRule] = &[

    // Common packers

    SectionRule {
        names: &[".upx0", ".upx1", ".upx2", "upx0", "upx1", "upx2"],
        severity: Severity::High,
        category: "Packed Binary",
        description: "UPX-style section names strongly suggest packing or unpacking stubs.",
    },
    SectionRule {
        names: &[".aspack", ".aspack0", ".aspack1"],
        severity: Severity::High,
        category: "Packed Binary",
        description: "ASPack-related section names suggest packed content.",
    },
    SectionRule {
        names: &[".mpress", ".mpress1", ".mpress2"],
        severity: Severity::High,
        category: "Packed Binary",
        description: "MPRESS-related section names suggest packing.",
    },
    SectionRule {
        names: &[".petite", ".petite0", ".petite1"],
        severity: Severity::High,
        category: "Packed Binary",
        description: "Petite-related section names suggest packing.",
    },
    SectionRule {
        names: &[".fsg", ".fsg0", ".fsg1"],
        severity: Severity::High,
        category: "Packed Binary",
        description: "FSG-related section names suggest packing.",
    },

    // Protectors / virtualizers

    SectionRule {
        names: &[".vmp0", ".vmp1", ".vmp2", ".vmp3", ".vmp"],
        severity: Severity::High,
        category: "Virtualized / Protected Binary",
        description: "VMProtect-style section names often indicate virtualization or protection.",
    },
    SectionRule {
        names: &[".themida", ".themida0", ".themida1"],
        severity: Severity::High,
        category: "Protected Binary",
        description: "Themida-related section names often indicate protection or packing.",
    },
    SectionRule {
        names: &[".armadillo", ".armadillo0", ".armadillo1"],
        severity: Severity::High,
        category: "Protected Binary",
        description: "Armadillo-related section names often indicate protection.",
    },
    SectionRule {
        names: &[".obsidium", ".obsidium0", ".obsidium1"],
        severity: Severity::High,
        category: "Protected Binary",
        description: "Obsidium-related section names often indicate protection.",
    },
    SectionRule {
        names: &[".enigma", ".enigma0", ".enigma1"],
        severity: Severity::High,
        category: "Protected Binary",
        description: "Enigma-related section names often indicate protection.",
    },

    // Generic suspicious custom names

    SectionRule {
        names: &[".stub", ".stub0", ".stub1"],
        severity: Severity::Medium,
        category: "Suspicious Section Layout",
        description: "Stub sections often appear in packed or loader-style binaries.",
    },
    SectionRule {
        names: &[".loader", ".loader0", ".loader1"],
        severity: Severity::Medium,
        category: "Suspicious Section Layout",
        description: "Loader-style section names can indicate custom loading logic.",
    },
    SectionRule {
        names: &[".payload", ".payload0", ".payload1"],
        severity: Severity::Medium,
        category: "Suspicious Section Layout",
        description: "Payload-style names may indicate embedded or unpacked code.",
    },
    SectionRule {
        names: &[".shell", ".shell0", ".shell1", ".shellcode"],
        severity: Severity::Medium,
        category: "Suspicious Section Layout",
        description: "Shell or shellcode-related section names are often suspicious.",
    },
    SectionRule {
        names: &[".packed", ".pack", ".packer"],
        severity: Severity::Medium,
        category: "Packed Binary",
        description: "Generic packing-related names suggest obfuscation or compression.",
    },
    SectionRule {
        names: &[".decrypt", ".unpack", ".unpacked"],
        severity: Severity::Medium,
        category: "Suspicious Section Layout",
        description: "Decryption or unpacking-related names can indicate staged payloads.",
    },
    SectionRule {
        names: &[".hidden", ".secret", ".enc", ".crypt", ".obf", ".obfuscated"],
        severity: Severity::Medium,
        category: "Obfuscated Data",
        description: "Names suggesting hidden, encrypted, or obfuscated content.",
    },
    SectionRule {
        names: &[".config", ".cfg", ".settings", ".meta", ".resourcex"],
        severity: Severity::Low,
        category: "Unusual Data Section",
        description: "Configuration-like custom section names are not necessarily bad, but worth noting.",
    },
];