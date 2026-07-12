//! Environment variable filtering — ports Go's `ssh/tailssh/accept_env.go`.
//!
//! The SSH client may request environment variables to be set in the session.
//! The tailnet policy file's `AcceptEnv` field controls which variables are
//! allowed. Patterns may contain `*` and `?` wildcards. Dangerous variables
//! (dynamic linker controls like `LD_PRELOAD`, `DYLD_*`) are always rejected
//! regardless of policy.

/// Reports whether the given environment variable name is unconditionally
/// prohibited from being forwarded, regardless of acceptEnv policy. This
/// prevents privilege escalation via dynamic linker environment variables.
fn is_dangerous_env_var(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.starts_with("LD_") || upper.starts_with("DYLD_")
}

/// Filter environment variables based on the acceptEnv allowlist.
///
/// `accept_env` is the slice of allowed variable name patterns (may contain
/// `*` and `?` wildcards). `environ` is the client-supplied environment in
/// `KEY=VALUE` format. Returns the filtered list of `KEY=VALUE` pairs that
/// pass both the allowlist and the dangerous-variable check.
pub fn filter_env(accept_env: &[String], environ: &[String]) -> Result<Vec<String>, String> {
    let mut accepted = Vec::new();

    if accept_env.is_empty() {
        return Ok(accepted);
    }

    for pair in environ {
        let (name, _) = match pair.split_once('=') {
            Some(parts) => parts,
            None => return Err(format!("invalid environment variable: {pair:?}")),
        };

        if is_dangerous_env_var(name) {
            continue;
        }

        if accept_env.iter().any(|p| p == name) || match_accept_env(accept_env, name) {
            accepted.push(pair.clone());
        }
    }

    Ok(accepted)
}

/// Check if any pattern in `accept_env` matches `name` using wildcard matching.
fn match_accept_env(accept_env: &[String], name: &str) -> bool {
    accept_env.iter().any(|p| match_pattern(p, name))
}

/// Match a pattern with `*` and `?` wildcards against a target string.
/// `*` matches zero or more characters, `?` matches exactly one character.
fn match_pattern(pattern: &str, target: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = target.chars().collect();
    let mut pi = 0;
    let mut ti = 0;

    loop {
        if pi >= p.len() {
            return ti >= t.len();
        }

        if p[pi] == '*' {
            while pi < p.len() && p[pi] == '*' {
                pi += 1;
            }
            if pi >= p.len() {
                return true;
            }
            while ti < t.len() {
                if match_pattern(&pattern[pi..], &target[ti..]) {
                    return true;
                }
                ti += 1;
            }
            return false;
        }

        if ti >= t.len() {
            return false;
        }

        if p[pi] != '?' && p[pi] != t[ti] {
            return false;
        }

        pi += 1;
        ti += 1;
    }
}

/// Default env var acceptance (mirrors Go's `acceptEnvPair` in incubator.go).
/// Accepts `TERM`, `LANG`, and `LC_*` variables unconditionally.
pub fn accept_env_pair(kv: &str) -> bool {
    let (key, _) = match kv.split_once('=') {
        Some(parts) => parts,
        None => return false,
    };
    key == "TERM" || key == "LANG" || key.starts_with("LC_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_env_vars() {
        assert!(is_dangerous_env_var("LD_PRELOAD"));
        assert!(is_dangerous_env_var("LD_LIBRARY_PATH"));
        assert!(is_dangerous_env_var("DYLD_INSERT_LIBRARIES"));
        assert!(is_dangerous_env_var("dyld_foo"));
        assert!(!is_dangerous_env_var("PATH"));
        assert!(!is_dangerous_env_var("TERM"));
    }

    #[test]
    fn test_filter_env_empty_accept() {
        let result = filter_env(&[], &["TERM=xterm".into()]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_env_exact_match() {
        let result = filter_env(
            &["TERM".into(), "LANG".into()],
            &["TERM=xterm".into(), "PATH=/bin".into()],
        )
        .unwrap();
        assert_eq!(result, vec!["TERM=xterm"]);
    }

    #[test]
    fn test_filter_env_wildcard() {
        let result = filter_env(
            &["LC_*".into()],
            &["LC_CTYPE=en_US".into(), "LC_ALL=C".into(), "TERM=xterm".into()],
        )
        .unwrap();
        assert_eq!(result, vec!["LC_CTYPE=en_US", "LC_ALL=C"]);
    }

    #[test]
    fn test_filter_env_rejects_dangerous() {
        let result = filter_env(
            &["*".into()],
            &[
                "LD_PRELOAD=/evil.so".into(),
                "DYLD_INSERT_LIBRARIES=/evil.so".into(),
                "TERM=xterm".into(),
            ],
        )
        .unwrap();
        assert_eq!(result, vec!["TERM=xterm"]);
    }

    #[test]
    fn test_match_pattern() {
        assert!(match_pattern("foo", "foo"));
        assert!(match_pattern("foo*", "foobar"));
        assert!(match_pattern("foo*", "foo"));
        assert!(match_pattern("*", "anything"));
        assert!(match_pattern("f?o", "foo"));
        assert!(match_pattern("f?o", "fao"));
        assert!(!match_pattern("f?o", "fooo"));
        assert!(match_pattern("LC_*", "LC_CTYPE"));
        assert!(match_pattern("LC_*", "LC_ALL"));
        assert!(!match_pattern("LC_*", "LANG"));
    }

    #[test]
    fn test_accept_env_pair() {
        assert!(accept_env_pair("TERM=xterm"));
        assert!(accept_env_pair("LANG=en_US.UTF-8"));
        assert!(accept_env_pair("LC_CTYPE=en_US"));
        assert!(accept_env_pair("LC_ALL=C"));
        assert!(!accept_env_pair("PATH=/bin"));
        assert!(!accept_env_pair("FOO=bar"));
    }
}
