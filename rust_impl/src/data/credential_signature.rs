use crate::models::Severity;

#[derive(Debug)]
pub struct CredentialRule {
    pub patterns: &'static [&'static str],
    pub severity: Severity,
    pub category: &'static str,
    pub description: &'static str,
}

pub const CREDENTIAL_RULES: &[CredentialRule] = &[
    CredentialRule {
        patterns: &[
            r"(?i)\bpassword\b",
            r"(?i)\bpasswd\b",
            r"(?i)\bpwd\b",
            r"(?i)\bpassphrase\b",
            r"(?i)\bpassword\s*=",
            r"(?i)\bpasswd\s*=",
            r"(?i)\bpwd\s*=",
        ],
        severity: Severity::High,
        category: "Password Material",
        description: "Password-related text or assignment.",
    },
    CredentialRule {
        patterns: &[
            r"(?i)\bsecret\b",
            r"(?i)\bclient_secret\b",
            r"(?i)\bapp_secret\b",
            r"(?i)\bprivate_key\b",
            r"(?i)\bbegin\s+rsa\s+private\s+key\b",
            r"(?i)\bbegin\s+openssh\s+private\s+key\b",
        ],
        severity: Severity::High,
        category: "Secret Material",
        description: "Secret or private-key related text.",
    },
    CredentialRule {
        patterns: &[
            r"(?i)\bapi[_-]?key\b",
            r"(?i)\baccess[_-]?token\b",
            r"(?i)\brefresh[_-]?token\b",
            r"(?i)\bid[_-]?token\b",
            r"(?i)\boauth[_-]?token\b",
            r"(?i)\bbearer[_-]?token\b",
            r"(?i)\btoken\s*=",
        ],
        severity: Severity::High,
        category: "API / Token Material",
        description: "API keys and token-like secrets.",
    },
    CredentialRule {
        patterns: &[
            r"(?i)\bauthorization\s*:",
            r"(?i)\bbearer\s+[A-Za-z0-9._\-+=/]+",
            r"(?i)\bauth[_-]?header\b",
        ],
        severity: Severity::High,
        category: "Authentication Material",
        description: "Authentication headers or bearer-token style text.",
    },
    CredentialRule {
        patterns: &[
            r"(?i)\busername\b",
            r"(?i)\blogin\b",
            r"(?i)\bsignin\b",
            r"(?i)\blogon\b",
            r"(?i)\bcredential\b",
            r"(?i)\bcredentials\b",
        ],
        severity: Severity::Low,
        category: "Login Context",
        description: "Login or credential-related context.",
    },
    CredentialRule {
        patterns: &[
            r"(?i)\bsession\b",
            r"(?i)\bcookie\b",
            r"(?i)\bcsrf\b",
            r"(?i)\bxsrf\b",
            r"(?i)\bjwt\b",
            r"(?i)\bsaml\b",
        ],
        severity: Severity::Medium,
        category: "Session / Web Auth",
        description: "Session or web-auth related context.",
    },
    CredentialRule {
        patterns: &[
            r"(?i)\botp\b",
            r"(?i)\bhotp\b",
            r"(?i)\btotp\b",
            r"(?i)\bmfa\b",
            r"(?i)\b2fa\b",
            r"(?i)\bpin\b",
        ],
        severity: Severity::Low,
        category: "Multi-Factor / PIN",
        description: "Multi-factor or PIN-related text.",
    },
    CredentialRule {
        patterns: &[
            r"(?i)\bkeystore\b",
            r"(?i)\bcertificate\b",
            r"(?i)\bcert\b",
            r"(?i)\bpem\b",
            r"(?i)\bpfx\b",
            r"(?i)\bp12\b",
            r"(?i)\bx509\b",
        ],
        severity: Severity::Medium,
        category: "Certificates / Keystores",
        description: "Certificate or keystore related text.",
    },
    CredentialRule {
        patterns: &[
            r"(?i)\baws_access_key_id\b",
            r"(?i)\baws_secret_access_key\b",
            r"(?i)\bgithub_token\b",
            r"(?i)\bgitlab_token\b",
            r"(?i)\bslack_bot_token\b",
            r"(?i)\bdiscord_bot_token\b",
            r"(?i)\bstripe_secret_key\b",
            r"(?i)\btwilio_auth_token\b",
            r"(?i)\bopenai_api_key\b",
            r"(?i)\bazure_client_secret\b",
        ],
        severity: Severity::High,
        category: "Cloud / Service Secrets",
        description: "Cloud or service secret markers.",
    },
];