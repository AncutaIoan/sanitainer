use once_cell::sync::Lazy;
use regex::Regex;

/// Built-in high-confidence secret patterns
pub fn builtin_patterns() -> Vec<Regex> {
    vec![
        Regex::new(r"(?i)\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b").unwrap(),
        Regex::new(r"(?i)\bgithub_pat_[0-9A-Za-z_]{22}_[0-9A-Za-z_]{59}\b").unwrap(),
        Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
        Regex::new(r"\bxox[baprs]-\d{10,}-\d{10,}-[A-Za-z0-9]{24,}\b").unwrap(),
        Regex::new(r"\bsk_(test|live)_[0-9a-zA-Z]{24,}\b").unwrap(),
        Regex::new(r"\b[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\b").unwrap(),
        Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----").unwrap(),
        Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----").unwrap(),
    ]
}

pub fn safe_allowlist_regexes() -> Vec<Regex> {
    static ALLOW: Lazy<Vec<Regex>> = Lazy::new(|| {
        vec![
            Regex::new(r"(?i)\bsha256:[a-f0-9]{64}\b").unwrap(),
            Regex::new(r"\b[0-9a-f]{7,40}\b").unwrap(),
            Regex::new(r"\b[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b").unwrap(),
            Regex::new(r"^[A-Za-z0-9+/=]{0,19}$").unwrap(),
        ]
    });
    ALLOW.clone()
}
