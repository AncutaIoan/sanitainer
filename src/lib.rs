mod patterns;
mod entropy;

use once_cell::sync::Lazy;
use regex::{Captures, Regex};

pub use entropy::shannon_entropy;
pub use patterns::{builtin_patterns, safe_allowlist_regexes};

/// Public options for sanitization.
#[derive(Debug, Clone)]
pub struct SanitizationOptions {
    /// Extra regex strings (PCRE-like as supported by Rust `regex`) to redact.
    pub custom_patterns: Vec<String>,
    /// Replacement text used when redacting.
    pub mask: String,
    /// Entropy threshold (bits/char) above which tokens are considered secrets.
    pub entropy_threshold: f64,
    /// Minimum candidate length for entropy scan.
    pub min_candidate_len: usize,
    /// If true, redact entire matching line when a secret is detected.
    pub redact_entire_line: bool,
}

impl Default for SanitizationOptions {
    fn default() -> Self {
        Self {
            custom_patterns: vec![],
            mask: "[REDACTED]".into(),
            entropy_threshold: 4.5,
            min_candidate_len: 20,
            redact_entire_line: false,
        }
    }
}

/// Sanitizes a log string according to builtin + custom rules and entropy scan.
pub fn sanitize_log(input: &str, opts: &SanitizationOptions) -> String {
    // 1) Exact-pattern redaction (builtins + custom)
    let mut out = redact_with_patterns(input, opts);

    // 2) Entropy-based pass (avoid allow-listed patterns)
    out = redact_high_entropy(&out, opts);

    out
}

/// Build a unified Regex that ORs all built-in and custom patterns.
/// We run them sequentially (not as one giant regex) to control behavior.
fn compile_all_patterns(custom: &[String]) -> Vec<Regex> {
    let mut patterns = builtin_patterns();
    for c in custom {
        if let Ok(re) = Regex::new(c) {
            patterns.push(re);
        }
    }
    patterns
}

fn redact_with_patterns(input: &str, opts: &SanitizationOptions) -> String {
    let patterns = compile_all_patterns(&opts.custom_patterns);
    let mut text = input.to_owned();

    for re in patterns {
        // Redact either the exact match or the whole line depending on flag.
        if opts.redact_entire_line {
            let line_re = Regex::new(&format!(r"(?m)^.*{}.*$", re.as_str())).unwrap();
            text = line_re.replace_all(&text, opts.mask.as_str()).into_owned();
        } else {
            text = re.replace_all(&text, opts.mask.as_str()).into_owned();
        }
    }

    text
}

/// Redact high-entropy tokens using a token-finder, then entropy check.
fn redact_high_entropy(input: &str, opts: &SanitizationOptions) -> String {
    // Candidate finder: long-ish URL-safe/base64/hex-like blobs.
    // Includes common token charsets and separators.
    static CANDIDATE_FINDER: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?x)
            (?P<prefix>(?i)(token|secret|password|passwd|pwd|bearer|authorization|auth|key|apikey|api_key|access[_-]?key|id[_-]?token)[=:]\s*)?
            (?P<val>
                [A-Za-z0-9_\-./+=]{20,}
            )
        ").unwrap()
    });

    let allowlist = safe_allowlist_regexes();

    CANDIDATE_FINDER
        .replace_all(input, |caps: &Captures| {
            let val = caps.name("val").map(|m| m.as_str()).unwrap_or("");
            let prefix = caps.name("prefix").map(|m| m.as_str()).unwrap_or("");

            if val.len() < opts.min_candidate_len {
                return caps.get(0).unwrap().as_str().to_string();
            }

            // Skip if allow-listed (e.g., sha256: digests, git SHAs near 40 hex, etc.)
            if allowlist.iter().any(|r| r.is_match(val)) {
                return caps.get(0).unwrap().as_str().to_string();
            }

            // JWT heuristic: three base64url parts separated by dots
            static JWT_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r"^[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?$").unwrap()
            });

            // Entropy based decision OR explicit JWT shape
            let ent = shannon_entropy(val);
            if ent >= opts.entropy_threshold || JWT_RE.is_match(val) {
                return if opts.redact_entire_line {
                    // Replace entire line
                    // (?m) ^.*VAL.*$
                    let line_re =
                        Regex::new(&format!("(?m)^.*{}.*$", regex::escape(val))).unwrap();
                    line_re.replace_all(input, opts.mask.as_str()).into_owned()
                } else {
                    // Replace just the value; keep prefix if present for readability
                    if !prefix.is_empty() {
                        format!("{}{}", prefix, opts.mask)
                    } else {
                        opts.mask.clone()
                    }
                }
            }

            caps.get(0).unwrap().as_str().to_string()
        })
        .into_owned()
}
