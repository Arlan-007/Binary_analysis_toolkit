use crate::models::Severity;

#[derive(Debug)]
pub struct CredentialRule {
    pub patterns: &'static [&'static str],
    pub severity: Severity,
    pub category: &'static str,
    pub description: &'static str,
    pub requires_value: bool,
}

pub const MIN_SECRET_VALUE_LENGTH: usize = 6;
pub const PLACEHOLDER_VALUE_PREFIXES: &[char] = &['%', '<', '{', '$', '*', '('];
pub const PLACEHOLDER_VALUE_MARKERS: &[&str] = &[
    "example",
    "changeme",
    "placeholder",
    "your_",
    "_here",
    "redacted",
    "dummy",
];

pub fn is_plausible(value: &str) -> bool {
    if value.len() < MIN_SECRET_VALUE_LENGTH {
        return false;
    }
    if value.starts_with(PLACEHOLDER_VALUE_PREFIXES) {
        return false;
    }
    if !value.chars().any(|c| c.is_ascii_alphanumeric()) {
        return false;
    }
    if let Some(first) = value.chars().next() {
        if value.chars().all(|c| c == first) {
            return false;
        }
    }
    let lower = value.to_lowercase();
    if PLACEHOLDER_VALUE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return false;
    }
    true
}

pub const CREDENTIAL_RULES: &[CredentialRule] = &[

    // Tier 1: standalone secret formats. A match is the secret itself.

    CredentialRule {
        patterns: &[
            r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",       // AWS access key id
            r"\bgh[pousr]_[A-Za-z0-9]{36}\b",         // GitHub token (ghp_, gho_, ...)
            r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",      // GitHub fine-grained PAT
            r"\bxox[baprs]-[A-Za-z0-9\-]{10,}",       // Slack token
            r"\b[sr]k_live_[A-Za-z0-9]{16,}\b",       // Stripe live key
            r"\bAIza[0-9A-Za-z_\-]{35}\b",            // Google API key
        ],
        severity: Severity::High,
        category: "Cloud / Service Secrets",
        description: "String matches a known cloud or service token format.",
        requires_value: false,
    },
    CredentialRule {
        patterns: &[
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",    // PEM private key header
        ],
        severity: Severity::High,
        category: "Secret Material",
        description: "Embedded PEM private key header.",
        requires_value: false,
    },
    CredentialRule {
        patterns: &[
            r"\beyJ[A-Za-z0-9_\-]{14,}\.[A-Za-z0-9._\-]{14,}", // JWT (header.payload)
        ],
        severity: Severity::High,
        category: "Session / Web Auth",
        description: "Embedded JWT-like token.",
        requires_value: false,
    },

    // Tier 2: key/value assignments. Group 1 must capture a plausible value.

    CredentialRule {
        patterns: &[
            r#"(?i)\b(?:aws_access_key_id|aws_secret_access_key|github_token|gitlab_token|slack_bot_token|discord_bot_token|stripe_secret_key|twilio_auth_token|openai_api_key|azure_client_secret)\s*[=:]\s*["']?([^\s"',;]+)"#,
        ],
        severity: Severity::High,
        category: "Cloud / Service Secrets",
        description: "Cloud or service secret assigned a concrete value.",
        requires_value: true,
    },
    CredentialRule {
        patterns: &[
            r#"(?i)\b(?:password|passwd|pwd|passphrase)\s*[=:]\s*["']?([^\s"',;]+)"#,
        ],
        severity: Severity::High,
        category: "Password Material",
        description: "Password assigned a concrete value.",
        requires_value: true,
    },
    CredentialRule {
        patterns: &[
            r#"(?i)\b(?:secret|client_secret|app_secret|api_secret|private_key)\s*[=:]\s*["']?([^\s"',;]+)"#,
        ],
        severity: Severity::High,
        category: "Secret Material",
        description: "Secret or private key assigned a concrete value.",
        requires_value: true,
    },
    CredentialRule {
        patterns: &[
            r#"(?i)\b(?:api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|id[_-]?token|oauth[_-]?token|bearer[_-]?token|auth[_-]?token|token)\s*[=:]\s*["']?([^\s"',;]+)"#,
        ],
        severity: Severity::High,
        category: "API / Token Material",
        description: "API key or token assigned a concrete value.",
        requires_value: true,
    },
    CredentialRule {
        patterns: &[
            r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+([A-Za-z0-9._+/=\-]{8,})",
        ],
        severity: Severity::High,
        category: "Authentication Material",
        description: "Full Authorization header with an embedded token.",
        requires_value: true,
    },

    // Tier 3: context keywords. Informational only (Severity::Low).

    CredentialRule {
        patterns: &[
            r"(?i)\b(?:password|passwd|passphrase)\b",
        ],
        severity: Severity::Low,
        category: "Password Material",
        description: "Password-related keyword (context only, no value seen).",
        requires_value: false,
    },
    CredentialRule {
        patterns: &[
            r"(?i)\b(?:username|login|signin|logon|credentials?)\b",
        ],
        severity: Severity::Low,
        category: "Login Context",
        description: "Login or credential-related keyword.",
        requires_value: false,
    },
    CredentialRule {
        patterns: &[
            r"(?i)\b(?:session|cookie|csrf|xsrf|jwt|saml)\b",
        ],
        severity: Severity::Low,
        category: "Session / Web Auth",
        description: "Session or web-auth related keyword.",
        requires_value: false,
    },
    CredentialRule {
        patterns: &[
            r"(?i)\b(?:otp|hotp|totp|mfa|2fa)\b",
        ],
        severity: Severity::Low,
        category: "Multi-Factor / PIN",
        description: "Multi-factor authentication related keyword.",
        requires_value: false,
    },
    CredentialRule {
        patterns: &[
            r"(?i)\b(?:keystore|truststore|certificate|x509|pkcs12)\b",
        ],
        severity: Severity::Low,
        category: "Certificates / Keystores",
        description: "Certificate or keystore related keyword.",
        requires_value: false,
    },
];
