#![allow(dead_code)]
use crate::models::Severity;

#[derive(Debug, Clone, Copy)]
pub struct RiskCategoryRule {
    pub category: &'static str,
    pub aliases: &'static [&'static str],
    pub family: &'static str,

    pub base_score: u32,
    pub incremental_score: u32,
    pub category_cap: u32,
    pub multiplier: f64,

    pub notes: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct RiskFamilyRule {
    pub family: &'static str,
    pub family_cap: u32,
    pub family_multiplier: f64,
    pub notes: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct RiskCategorySynergyRule {
    pub category_a: &'static str,
    pub category_b: &'static str,
    pub bonus: u32,
    pub bonus_cap: u32,
    pub notes: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub struct RiskFamilySynergyRule {
    pub family_a: &'static str,
    pub family_b: &'static str,
    pub bonus: u32,
    pub bonus_cap: u32,
    pub notes: &'static str,
}

pub const LOW_RISK_MAX: u32 = 19;
pub const MEDIUM_RISK_MAX: u32 = 39;
pub const HIGH_RISK_MAX: u32 = 69;
pub const MAX_RISK_SCORE: u32 = 100;

pub const SEVERITY_LOW_POINTS: u32 = 5;
pub const SEVERITY_MEDIUM_POINTS: u32 = 10;
pub const SEVERITY_HIGH_POINTS: u32 = 20;
pub const SEVERITY_CRITICAL_POINTS: u32 = 30;

pub const SEVERITY_LOW_MULTIPLIER: f64 = 1.00;
pub const SEVERITY_MEDIUM_MULTIPLIER: f64 = 1.15;
pub const SEVERITY_HIGH_MULTIPLIER: f64 = 1.35;
pub const SEVERITY_CRITICAL_MULTIPLIER: f64 = 1.60;

pub const CATEGORY_REPEAT_DECAY_START: usize = 2;
pub const CATEGORY_REPEAT_DECAY_FACTOR: f64 = 0.70;
pub const FAMILY_REPEAT_DECAY_FACTOR: f64 = 0.85;
pub const SYNERGY_REPEAT_DECAY_FACTOR: f64 = 0.90;

pub const DEFAULT_CATEGORY_RULE: RiskCategoryRule = RiskCategoryRule {
    category: "Unknown",
    aliases: &[],
    family: "Misc",
    base_score: 1,
    incremental_score: 1,
    category_cap: 6,
    multiplier: 0.50,
    notes: "Fallback rule for uncategorized findings.",
};

pub const DEFAULT_FAMILY_RULE: RiskFamilyRule = RiskFamilyRule {
    family: "Misc",
    family_cap: 8,
    family_multiplier: 0.50,
    notes: "Fallback family for uncategorized findings.",
};

pub const RISK_FAMILY_RULES: &[RiskFamilyRule] = &[
    RiskFamilyRule {
        family: "Process Activity",
        family_cap: 35,
        family_multiplier: 1.40,
        notes: "Remote memory, injection, and process manipulation behavior.",
    },
    RiskFamilyRule {
        family: "Execution",
        family_cap: 24,
        family_multiplier: 1.20,
        notes: "Process launch, runtime loading, and command execution behavior.",
    },
    RiskFamilyRule {
        family: "Network Activity",
        family_cap: 18,
        family_multiplier: 0.90,
        notes: "Embedded URLs/IPs and networking behavior.",
    },
    RiskFamilyRule {
        family: "Persistence",
        family_cap: 28,
        family_multiplier: 1.60,
        notes: "Registry, service, and autostart-style persistence behavior.",
    },
    RiskFamilyRule {
        family: "Anti Analysis",
        family_cap: 24,
        family_multiplier: 1.45,
        notes: "Timing, anti-debugging, and evasion logic.",
    },
    RiskFamilyRule {
        family: "Credentials",
        family_cap: 32,
        family_multiplier: 2.00,
        notes: "Hardcoded secrets, tokens, password material, and related auth data.",
    },
    RiskFamilyRule {
        family: "Obfuscation",
        family_cap: 36,
        family_multiplier: 2.10,
        notes: "Packing, protection, encoded data, entropy anomalies, and obfuscation.",
    },
    RiskFamilyRule {
        family: "File System",
        family_cap: 12,
        family_multiplier: 0.80,
        notes: "Ordinary file operations are common and usually weak on their own.",
    },
    RiskFamilyRule {
        family: "Input Interception",
        family_cap: 20,
        family_multiplier: 1.60,
        notes: "Hooking and input capture-style behavior.",
    },
    RiskFamilyRule {
        family: "Environment",
        family_cap: 10,
        family_multiplier: 0.70,
        notes: "Process enumeration and environment inspection are weak signals alone.",
    },
    RiskFamilyRule {
        family: "Cryptography",
        family_cap: 14,
        family_multiplier: 1.00,
        notes: "Crypto API usage can be normal, so it should stay modest.",
    },
    RiskFamilyRule {
        family: "Control Flow",
        family_cap: 24,
        family_multiplier: 1.70,
        notes: "Capstone-era control-flow abnormalities and suspicious instruction patterns.",
    },
    RiskFamilyRule {
        family: "Metadata",
        family_cap: 4,
        family_multiplier: 0.30,
        notes: "Imports, exports, symbols, and debug metadata are not suspicious by themselves.",
    },
    RiskFamilyRule {
        family: "Misc",
        family_cap: 8,
        family_multiplier: 0.50,
        notes: "Fallback family for unmatched categories.",
    },
];

pub const RISK_CATEGORY_RULES: &[RiskCategoryRule] = &[
    // Process manipulation
    RiskCategoryRule {
        category: "Process Injection",
        aliases: &[
            "Memory Manipulation",
            "Shellcode Staging",
            "Remote Thread Injection",
            "Code Injection",
            "Process Injection / Memory Manipulation",
        ],
        family: "Process Activity",
        base_score: 18,
        incremental_score: 4,
        category_cap: 35,
        multiplier: 2.30,
        notes: "Strong signal for injection, staging, or unpacking behavior.",
    },
    RiskCategoryRule {
        category: "Process Inspection",
        aliases: &["Debugger-like", "Memory Inspection"],
        family: "Process Activity",
        base_score: 10,
        incremental_score: 3,
        category_cap: 20,
        multiplier: 1.50,
        notes: "Reading or inspecting process memory is often used by debuggers or malware tooling.",
    },
    RiskCategoryRule {
        category: "Process Creation",
        aliases: &["Process Launch", "Spawn Process"],
        family: "Execution",
        base_score: 9,
        incremental_score: 3,
        category_cap: 20,
        multiplier: 1.40,
        notes: "Creating child processes can be legitimate but is more meaningful in bulk.",
    },
    RiskCategoryRule {
        category: "Privilege Escalation",
        aliases: &["Token Abuse", "Privilege Abuse"],
        family: "Process Activity",
        base_score: 12,
        incremental_score: 4,
        category_cap: 24,
        multiplier: 2.00,
        notes: "Token handling and privilege abuse are strong behavioral signals.",
    },

    // Runtime loading / execution
    RiskCategoryRule {
        category: "Dynamic Loading",
        aliases: &["Runtime Loading", "Late Binding", "API Resolution"],
        family: "Execution",
        base_score: 7,
        incremental_score: 2,
        category_cap: 15,
        multiplier: 1.15,
        notes: "Runtime DLL loading and late binding are useful but often legitimate.",
    },
    RiskCategoryRule {
        category: "Shell Execution",
        aliases: &["Shell Run", "Shell Launch"],
        family: "Execution",
        base_score: 12,
        incremental_score: 3,
        category_cap: 20,
        multiplier: 1.50,
        notes: "Launching via shell is often more suspicious than a direct process start.",
    },
    RiskCategoryRule {
        category: "Command Execution",
        aliases: &["Cmd Execution", "System Command"],
        family: "Execution",
        base_score: 14,
        incremental_score: 4,
        category_cap: 22,
        multiplier: 1.70,
        notes: "Direct command execution is higher risk than generic process spawning.",
    },

    // Networking / network indicators
    RiskCategoryRule {
        category: "Networking",
        aliases: &[
            "Network Indicator",
            "Network Indicators",
            "URL",
            "IP",
            "Embedded URL",
            "Embedded IP",
        ],
        family: "Network Activity",
        base_score: 4,
        incremental_score: 1,
        category_cap: 12,
        multiplier: 0.90,
        notes: "URLs, IPs, and basic networking APIs are common and should stay modest.",
    },
    RiskCategoryRule {
        category: "Network Indicator",
        aliases: &["URL", "IP", "Domain", "Host"],
        family: "Network Activity",
        base_score: 4,
        incremental_score: 1,
        category_cap: 12,
        multiplier: 0.90,
        notes: "Embedded network indicators should be weak unless paired with stronger evidence.",
    },

    // Persistence / registry / services
    RiskCategoryRule {
        category: "Registry",
        aliases: &["Windows Registry"],
        family: "Persistence",
        base_score: 7,
        incremental_score: 2,
        category_cap: 16,
        multiplier: 1.35,
        notes: "Registry access is often legitimate, but repeated modification is meaningful.",
    },
    RiskCategoryRule {
        category: "Service Control",
        aliases: &["Windows Service Control", "SCM"],
        family: "Persistence",
        base_score: 12,
        incremental_score: 4,
        category_cap: 25,
        multiplier: 1.70,
        notes: "Service installation or control is a stronger persistence indicator.",
    },
    RiskCategoryRule {
        category: "Scheduled Task",
        aliases: &["Task Scheduler", "Autostart Task"],
        family: "Persistence",
        base_score: 12,
        incremental_score: 4,
        category_cap: 22,
        multiplier: 1.60,
        notes: "Scheduled tasks are a common persistence technique.",
    },
    RiskCategoryRule {
        category: "Persistence",
        aliases: &["Autostart", "Startup Persistence"],
        family: "Persistence",
        base_score: 10,
        incremental_score: 3,
        category_cap: 20,
        multiplier: 1.50,
        notes: "Generic persistence behavior.",
    },

    // File system / local system actions
    RiskCategoryRule {
        category: "File Operations",
        aliases: &["Filesystem", "File System"],
        family: "File System",
        base_score: 3,
        incremental_score: 1,
        category_cap: 8,
        multiplier: 0.70,
        notes: "File I/O is common; keep it low unless combined with stronger evidence.",
    },

    // Anti-analysis / debugger / timing
    RiskCategoryRule {
        category: "Anti-Debugging",
        aliases: &["Anti Debugging", "AntiDebug"],
        family: "Anti Analysis",
        base_score: 12,
        incremental_score: 3,
        category_cap: 24,
        multiplier: 1.90,
        notes: "Debugger checks are more suspicious than timing alone.",
    },
    RiskCategoryRule {
        category: "Timing",
        aliases: &["Anti Timing", "Anti-Analysis Timing"],
        family: "Anti Analysis",
        base_score: 4,
        incremental_score: 1,
        category_cap: 10,
        multiplier: 0.70,
        notes: "Timing checks are weak alone but useful as supporting evidence.",
    },
    RiskCategoryRule {
        category: "Environment Inspection",
        aliases: &["Environment", "Host Inspection"],
        family: "Anti Analysis",
        base_score: 4,
        incremental_score: 1,
        category_cap: 10,
        multiplier: 0.80,
        notes: "Environment inspection is a weak signal on its own.",
    },

    // Crypto / obfuscation-adjacent
    RiskCategoryRule {
        category: "Cryptography",
        aliases: &["Crypto", "CryptoAPI"],
        family: "Cryptography",
        base_score: 5,
        incremental_score: 2,
        category_cap: 12,
        multiplier: 1.00,
        notes: "Crypto usage can be normal, so it should not dominate the score.",
    },

    // Credential / secret material
    RiskCategoryRule {
        category: "Credentials",
        aliases: &[
            "Hardcoded Credential",
            "Hardcoded Credentials",
            "Secret Material",
            "Password Material",
            "API / Token Material",
            "Authentication Material",
            "Login Context",
            "Session / Web Auth",
            "Multi-Factor / PIN",
            "Certificates / Keystores",
            "Cloud / Service Secrets",
        ],
        family: "Credentials",
        base_score: 12,
        incremental_score: 3,
        category_cap: 24,
        multiplier: 2.00,
        notes: "Generic credential-related evidence.",
    },
    RiskCategoryRule {
        category: "Password Material",
        aliases: &["Password", "Passphrase"],
        family: "Credentials",
        base_score: 18,
        incremental_score: 4,
        category_cap: 30,
        multiplier: 2.40,
        notes: "Password material is high-value and should be scored strongly.",
    },
    RiskCategoryRule {
        category: "Secret Material",
        aliases: &["Private Key Material", "Secret", "Private Key"],
        family: "Credentials",
        base_score: 18,
        incremental_score: 4,
        category_cap: 30,
        multiplier: 2.40,
        notes: "Secrets and private keys are high-value evidence.",
    },
    RiskCategoryRule {
        category: "API / Token Material",
        aliases: &["Token Material", "Access Token", "Bearer Token"],
        family: "Credentials",
        base_score: 16,
        incremental_score: 4,
        category_cap: 28,
        multiplier: 2.20,
        notes: "API keys and tokens are strong indicators of embedded secrets.",
    },
    RiskCategoryRule {
        category: "Authentication Material",
        aliases: &["Auth Header", "Authorization Header"],
        family: "Credentials",
        base_score: 14,
        incremental_score: 3,
        category_cap: 24,
        multiplier: 2.00,
        notes: "Authentication headers and bearer-style material are sensitive.",
    },
    RiskCategoryRule {
        category: "Login Context",
        aliases: &["Username", "Login", "Sign In", "Logon", "Credential Context"],
        family: "Credentials",
        base_score: 3,
        incremental_score: 1,
        category_cap: 8,
        multiplier: 0.50,
        notes: "Login context alone is weak and should not drive risk heavily.",
    },
    RiskCategoryRule {
        category: "Session / Web Auth",
        aliases: &["Session", "Cookie", "CSRF", "XSRF", "JWT", "SAML"],
        family: "Credentials",
        base_score: 8,
        incremental_score: 2,
        category_cap: 16,
        multiplier: 1.20,
        notes: "Session artifacts can matter, but are not always malicious.",
    },
    RiskCategoryRule {
        category: "Multi-Factor / PIN",
        aliases: &["OTP", "HOTP", "TOTP", "MFA", "2FA", "PIN"],
        family: "Credentials",
        base_score: 4,
        incremental_score: 1,
        category_cap: 8,
        multiplier: 0.60,
        notes: "Usually not suspicious on its own.",
    },
    RiskCategoryRule {
        category: "Certificates / Keystores",
        aliases: &["Certificate", "Cert", "PEM", "PFX", "P12", "X509"],
        family: "Credentials",
        base_score: 6,
        incremental_score: 2,
        category_cap: 12,
        multiplier: 0.90,
        notes: "Certificates can be benign, so keep this conservative.",
    },
    RiskCategoryRule {
        category: "Cloud / Service Secrets",
        aliases: &[
            "AWS Access Key",
            "AWS Secret Access Key",
            "GitHub Token",
            "GitLab Token",
            "Slack Bot Token",
            "Discord Bot Token",
            "Stripe Secret Key",
            "Twilio Auth Token",
            "OpenAI API Key",
            "Azure Client Secret",
        ],
        family: "Credentials",
        base_score: 20,
        incremental_score: 4,
        category_cap: 32,
        multiplier: 2.60,
        notes: "Cloud and service secrets are highly sensitive.",
    },

    // Hooks / input interception
    RiskCategoryRule {
        category: "Hooking",
        aliases: &["Input Hooking", "Keyboard Hooking"],
        family: "Input Interception",
        base_score: 16,
        incremental_score: 4,
        category_cap: 28,
        multiplier: 2.10,
        notes: "Hooks often indicate interception or keylogging style behavior.",
    },
    RiskCategoryRule {
        category: "Input Interception",
        aliases: &["Keylogging", "Hotkey Interception"],
        family: "Input Interception",
        base_score: 10,
        incremental_score: 3,
        category_cap: 18,
        multiplier: 1.60,
        notes: "Input interception is meaningful but not always malicious.",
    },

    // Enumeration / environment probing
    RiskCategoryRule {
        category: "Process Enumeration",
        aliases: &["Process List", "Snapshot Enumeration"],
        family: "Environment",
        base_score: 3,
        incremental_score: 1,
        category_cap: 8,
        multiplier: 0.60,
        notes: "Process enumeration is weak unless paired with other evidence.",
    },

    // Obfuscation / packing / entropy / encoded data
    RiskCategoryRule {
        category: "Packing",
        aliases: &["Packed Binary", "Packer"],
        family: "Obfuscation",
        base_score: 20,
        incremental_score: 0,
        category_cap: 35,
        multiplier: 2.50,
        notes: "Packing is a strong signal and should carry major weight.",
    },
    RiskCategoryRule {
        category: "Packed Binary",
        aliases: &["Packing", "Packer"],
        family: "Obfuscation",
        base_score: 20,
        incremental_score: 0,
        category_cap: 35,
        multiplier: 2.50,
        notes: "Packed binary conclusion from heuristics.",
    },
    RiskCategoryRule {
        category: "Virtualized / Protected Binary",
        aliases: &["Virtualized Binary", "Protected Binary"],
        family: "Obfuscation",
        base_score: 18,
        incremental_score: 0,
        category_cap: 30,
        multiplier: 2.30,
        notes: "Virtualized/protected binaries often hide code paths.",
    },
    RiskCategoryRule {
        category: "Protected Binary",
        aliases: &["Protection", "Protectors"],
        family: "Obfuscation",
        base_score: 16,
        incremental_score: 0,
        category_cap: 28,
        multiplier: 2.10,
        notes: "General binary protection is suspicious when combined with other evidence.",
    },
    RiskCategoryRule {
        category: "Suspicious Section Layout",
        aliases: &["Section Layout", "Suspicious Section"],
        family: "Obfuscation",
        base_score: 8,
        incremental_score: 2,
        category_cap: 16,
        multiplier: 1.30,
        notes: "Odd section layout supports packing or manual mapping hypotheses.",
    },
    RiskCategoryRule {
        category: "Obfuscated Data",
        aliases: &["Obfuscation", "Hidden Data", "Encrypted Data"],
        family: "Obfuscation",
        base_score: 10,
        incremental_score: 2,
        category_cap: 18,
        multiplier: 1.80,
        notes: "Hidden or encrypted data should be treated as suspicious evidence.",
    },
    RiskCategoryRule {
        category: "Unusual Data Section",
        aliases: &["Custom Data Section", "Odd Data Section"],
        family: "Obfuscation",
        base_score: 4,
        incremental_score: 1,
        category_cap: 10,
        multiplier: 0.80,
        notes: "Not necessarily bad, but can support an obfuscation story.",
    },
    RiskCategoryRule {
        category: "Encoded String",
        aliases: &["Base64 Encoded String", "Hex Encoded String", "High Entropy String"],
        family: "Obfuscation",
        base_score: 5,
        incremental_score: 1,
        category_cap: 12,
        multiplier: 1.00,
        notes: "Encoded strings are evidence, not proof.",
    },
    RiskCategoryRule {
        category: "Entropy",
        aliases: &["Section Entropy", "String Entropy", "High Entropy Section"],
        family: "Obfuscation",
        base_score: 8,
        incremental_score: 2,
        category_cap: 16,
        multiplier: 1.60,
        notes: "Entropy anomalies support packing/compression/obfuscation hypotheses.",
    },
    RiskCategoryRule {
        category: "Suspicious Import",
        aliases: &["Suspicious Imports", "Import"],
        family: "Execution",
        base_score: 6,
        incremental_score: 2,
        category_cap: 14,
        multiplier: 1.00,
        notes: "Fallback suspicious-import bucket.",
    },

    // Metadata and low-signal future-proofing
    RiskCategoryRule {
        category: "Import Table",
        aliases: &["Imports", "IAT", "Import Metadata"],
        family: "Metadata",
        base_score: 0,
        incremental_score: 0,
        category_cap: 2,
        multiplier: 0.20,
        notes: "Import metadata by itself is informational.",
    },
    RiskCategoryRule {
        category: "Export Table",
        aliases: &["Exports", "EAT", "Export Metadata"],
        family: "Metadata",
        base_score: 0,
        incremental_score: 0,
        category_cap: 2,
        multiplier: 0.20,
        notes: "Export metadata is informational.",
    },
    RiskCategoryRule {
        category: "Symbol Table",
        aliases: &["Symbols", "Dynsym", "Symtab"],
        family: "Metadata",
        base_score: 0,
        incremental_score: 0,
        category_cap: 2,
        multiplier: 0.20,
        notes: "Symbol metadata is informational.",
    },
    RiskCategoryRule {
        category: "Debug Symbols",
        aliases: &["Debug Metadata", "PDB"],
        family: "Metadata",
        base_score: 0,
        incremental_score: 0,
        category_cap: 2,
        multiplier: 0.20,
        notes: "Debug metadata is informational.",
    },

    // Future Capstone / disassembly-era categories
    RiskCategoryRule {
        category: "Control Flow Manipulation",
        aliases: &["Control Flow", "Branch Manipulation", "Indirect Control Transfer"],
        family: "Control Flow",
        base_score: 12,
        incremental_score: 4,
        category_cap: 24,
        multiplier: 1.80,
        notes: "Suspicious control-flow patterns should matter more once disassembly lands.",
    },
    RiskCategoryRule {
        category: "Suspicious Instruction Sequence",
        aliases: &["Suspicious Instructions", "Instruction Anomaly"],
        family: "Control Flow",
        base_score: 10,
        incremental_score: 3,
        category_cap: 20,
        multiplier: 1.50,
        notes: "Unusual instruction sequences can indicate obfuscation or anti-analysis logic.",
    },
    RiskCategoryRule {
        category: "Syscall",
        aliases: &["Direct Syscall", "Native API"],
        family: "Control Flow",
        base_score: 12,
        incremental_score: 3,
        category_cap: 24,
        multiplier: 1.80,
        notes: "Direct syscalls can indicate evasion or low-level runtime manipulation.",
    },
    RiskCategoryRule {
        category: "Self-Modifying Code",
        aliases: &["Runtime Patching", "Code Mutation"],
        family: "Control Flow",
        base_score: 18,
        incremental_score: 4,
        category_cap: 30,
        multiplier: 2.40,
        notes: "Self-modifying code is a strong obfuscation / evasion indicator.",
    },
    RiskCategoryRule {
        category: "Trampoline",
        aliases: &["JMP Trampoline", "Call Trampoline"],
        family: "Control Flow",
        base_score: 8,
        incremental_score: 2,
        category_cap: 16,
        multiplier: 1.20,
        notes: "Trampoline-style control flow is useful but not always malicious.",
    },
    RiskCategoryRule {
        category: "Stack Pivot",
        aliases: &["Pivot", "Stack Manipulation"],
        family: "Control Flow",
        base_score: 14,
        incremental_score: 4,
        category_cap: 24,
        multiplier: 2.00,
        notes: "Stack pivots are high-risk and usually worth strong weighting.",
    },
    RiskCategoryRule {
        category: "ROP Gadget",
        aliases: &["ROP", "Gadget"],
        family: "Control Flow",
        base_score: 12,
        incremental_score: 3,
        category_cap: 20,
        multiplier: 1.70,
        notes: "ROP-related findings matter once instruction-level analysis exists.",
    },
];

pub const RISK_CATEGORY_SYNERGY_RULES: &[RiskCategorySynergyRule] = &[
    RiskCategorySynergyRule {
        category_a: "Packing",
        category_b: "Process Injection",
        bonus: 12,
        bonus_cap: 20,
        notes: "Packed binaries combined with injection-style behavior are much more suspicious.",
    },
    RiskCategorySynergyRule {
        category_a: "Packing",
        category_b: "Anti-Debugging",
        bonus: 8,
        bonus_cap: 12,
        notes: "Packed binaries plus anti-debugging strongly support evasion.",
    },
    RiskCategorySynergyRule {
        category_a: "Packing",
        category_b: "Dynamic Loading",
        bonus: 8,
        bonus_cap: 12,
        notes: "Packing with runtime loading is a common obfuscation pattern.",
    },
    RiskCategorySynergyRule {
        category_a: "Packing",
        category_b: "Entropy",
        bonus: 8,
        bonus_cap: 12,
        notes: "Packing plus entropy anomalies strongly support obfuscation.",
    },
    RiskCategorySynergyRule {
        category_a: "Process Injection",
        category_b: "Dynamic Loading",
        bonus: 8,
        bonus_cap: 12,
        notes: "Injection with runtime loading is a strong behavioral combination.",
    },
    RiskCategorySynergyRule {
        category_a: "Registry",
        category_b: "Service Control",
        bonus: 8,
        bonus_cap: 12,
        notes: "Registry plus service control is a classic persistence combination.",
    },
    RiskCategorySynergyRule {
        category_a: "Registry",
        category_b: "Process Creation",
        bonus: 5,
        bonus_cap: 10,
        notes: "Registry activity and process spawning together can indicate staged behavior.",
    },
    RiskCategorySynergyRule {
        category_a: "Credentials",
        category_b: "Networking",
        bonus: 8,
        bonus_cap: 14,
        notes: "Embedded secrets plus network behavior raise suspicion.",
    },
    RiskCategorySynergyRule {
        category_a: "Encoded String",
        category_b: "Networking",
        bonus: 5,
        bonus_cap: 10,
        notes: "Encoded network indicators are often more interesting than plain-text ones.",
    },
    RiskCategorySynergyRule {
        category_a: "Entropy",
        category_b: "Suspicious Section Layout",
        bonus: 8,
        bonus_cap: 12,
        notes: "Entropy anomalies plus odd section layout support packing or protection.",
    },
    RiskCategorySynergyRule {
        category_a: "Timing",
        category_b: "Anti-Debugging",
        bonus: 6,
        bonus_cap: 10,
        notes: "Timing-based checks plus debugger checks are stronger together.",
    },
    RiskCategorySynergyRule {
        category_a: "Hooking",
        category_b: "Input Interception",
        bonus: 8,
        bonus_cap: 12,
        notes: "Hooks plus interception behavior often go together.",
    },
    RiskCategorySynergyRule {
        category_a: "Syscall",
        category_b: "Control Flow Manipulation",
        bonus: 6,
        bonus_cap: 10,
        notes: "Direct syscalls plus unusual control flow can indicate evasion.",
    },
    RiskCategorySynergyRule {
        category_a: "Self-Modifying Code",
        category_b: "Packing",
        bonus: 10,
        bonus_cap: 16,
        notes: "Self-modifying code plus packing is a strong obfuscation combination.",
    },
];

pub const RISK_FAMILY_SYNERGY_RULES: &[RiskFamilySynergyRule] = &[
    RiskFamilySynergyRule {
        family_a: "Obfuscation",
        family_b: "Process Activity",
        bonus: 8,
        bonus_cap: 15,
        notes: "Obfuscation combined with process manipulation is far more concerning.",
    },
    RiskFamilySynergyRule {
        family_a: "Obfuscation",
        family_b: "Anti Analysis",
        bonus: 8,
        bonus_cap: 15,
        notes: "Obfuscation combined with anti-analysis techniques is strongly suspicious.",
    },
    RiskFamilySynergyRule {
        family_a: "Credentials",
        family_b: "Network Activity",
        bonus: 8,
        bonus_cap: 16,
        notes: "Secrets plus network indicators increase the chance of exfiltration or C2.",
    },
    RiskFamilySynergyRule {
        family_a: "Persistence",
        family_b: "Process Activity",
        bonus: 6,
        bonus_cap: 12,
        notes: "Persistence plus process manipulation is more suspicious than either alone.",
    },
    RiskFamilySynergyRule {
        family_a: "Persistence",
        family_b: "Network Activity",
        bonus: 4,
        bonus_cap: 10,
        notes: "Persistence plus networking can indicate staged or remote control behavior.",
    },
    RiskFamilySynergyRule {
        family_a: "Execution",
        family_b: "Anti Analysis",
        bonus: 5,
        bonus_cap: 10,
        notes: "Runtime loading or execution behavior combined with evasion is meaningful.",
    },
    RiskFamilySynergyRule {
        family_a: "File System",
        family_b: "Persistence",
        bonus: 5,
        bonus_cap: 10,
        notes: "File-system actions plus persistence often show staging or installation logic.",
    },
    RiskFamilySynergyRule {
        family_a: "Input Interception",
        family_b: "Credentials",
        bonus: 8,
        bonus_cap: 14,
        notes: "Input interception plus credentials can point toward theft or capture behavior.",
    },
    RiskFamilySynergyRule {
        family_a: "Cryptography",
        family_b: "Obfuscation",
        bonus: 4,
        bonus_cap: 8,
        notes: "Crypto plus obfuscation can be legitimate but is worth slightly more together.",
    },
    RiskFamilySynergyRule {
        family_a: "Control Flow",
        family_b: "Obfuscation",
        bonus: 8,
        bonus_cap: 16,
        notes: "Disassembly-era control-flow anomalies plus obfuscation are a strong pair.",
    },
];

fn name_matches(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

pub fn severity_points(severity: &Severity) -> u32 {
    match severity {
        Severity::Low => SEVERITY_LOW_POINTS,
        Severity::Medium => SEVERITY_MEDIUM_POINTS,
        Severity::High => SEVERITY_HIGH_POINTS,
        Severity::Critical => SEVERITY_CRITICAL_POINTS,
    }
}

pub fn severity_multiplier(severity: &Severity) -> f64 {
    match severity {
        Severity::Low => SEVERITY_LOW_MULTIPLIER,
        Severity::Medium => SEVERITY_MEDIUM_MULTIPLIER,
        Severity::High => SEVERITY_HIGH_MULTIPLIER,
        Severity::Critical => SEVERITY_CRITICAL_MULTIPLIER,
    }
}

pub fn rule_for_category(category: &str) -> &'static RiskCategoryRule {
    RISK_CATEGORY_RULES
        .iter()
        .find(|rule| {
            name_matches(rule.category, category)
                || rule.aliases.iter().any(|alias| name_matches(alias, category))
        })
        .unwrap_or(&DEFAULT_CATEGORY_RULE)
}

pub fn family_for_category(category: &str) -> &'static str {
    rule_for_category(category).family
}

pub fn family_rule_for(family: &str) -> &'static RiskFamilyRule {
    RISK_FAMILY_RULES
        .iter()
        .find(|rule| name_matches(rule.family, family))
        .unwrap_or(&DEFAULT_FAMILY_RULE)
}

pub fn canonical_category_name(category: &str) -> &'static str {
    rule_for_category(category).category
}