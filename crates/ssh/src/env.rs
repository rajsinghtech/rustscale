//! Environment variable filtering — ports Go's `ssh/tailssh/accept_env.go`.

fn is_dangerous_env_var(name: &str) -> bool {
    let upper = name.to_uppercase();
    upper.starts_with("LD_") || upper.starts_with("DYLD_")
}

pub fn filter_env(accept_env: &[String], environ: &[String]) -> Result<Vec<String>, String> {
    let mut accepted = Vec::new();
    if accept_env.is_empty() { return Ok(accepted); }
    for pair in environ {
        let (name, _) = match pair.split_once('=') {
            Some(parts) => parts,
            None => return Err(format!("invalid environment variable: {pair:?}")),
        };
        if is_dangerous_env_var(name) { continue; }
        if accept_env.iter().any(|p| p == name) || match_accept_env(accept_env, name) {
            accepted.push(pair.clone());
        }
    }
    Ok(accepted)
}

fn match_accept_env(accept_env: &[String], name: &str) -> bool {
    accept_env.iter().any(|p| match_pattern(p, name))
}

fn match_pattern(pattern: &str, target: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = target.chars().collect();
    let mut pi = 0;
    let mut ti = 0;
    loop {
        if pi >= p.len() { return ti >= t.len(); }
        if p[pi] == '*' {
            while pi < p.len() && p[pi] == '*' { pi += 1; }
            if pi >= p.len() { return true; }
            while ti < t.len() {
                if match_pattern(&pattern[pi..], &target[ti..]) { return true; }
                ti += 1;
            }
            return false;
        }
        if ti >= t.len() { return false; }
        if p[pi] != '?' && p[pi] != t[ti] { return false; }
        pi += 1;
        ti += 1;
    }
}

pub fn accept_env_pair(kv: &str) -> bool {
    let (key, _) = match kv.split_once('=') { Some(p) => p, None => return false };
    key == "TERM" || key == "LANG" || key.starts_with("LC_")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dangerous_env_vars() {
        assert!(is_dangerous_env_var("LD_PRELOAD"));
        assert!(is_dangerous_env_var("DYLD_INSERT_LIBRARIES"));
        assert!(!is_dangerous_env_var("PATH"));
    }
    #[test]
    fn test_filter_env_empty() { assert!(filter_env(&[], &["TERM=xterm".into()]).unwrap().is_empty()); }
    #[test]
    fn test_filter_env_exact() {
        assert_eq!(filter_env(&["TERM".into()], &["TERM=xterm".into(), "PATH=/bin".into()]).unwrap(), vec!["TERM=xterm"]);
    }
    #[test]
    fn test_filter_env_wildcard() {
        assert_eq!(filter_env(&["LC_*".into()], &["LC_CTYPE=en".into(), "LC_ALL=C".into(), "TERM=x".into()]).unwrap(), vec!["LC_CTYPE=en", "LC_ALL=C"]);
    }
    #[test]
    fn test_filter_env_rejects_dangerous() {
        assert_eq!(filter_env(&["*".into()], &["LD_PRELOAD=/x".into(), "TERM=x".into()]).unwrap(), vec!["TERM=x"]);
    }
    #[test]
    fn test_match_pattern() {
        assert!(match_pattern("foo", "foo"));
        assert!(match_pattern("foo*", "foobar"));
        assert!(match_pattern("*", "anything"));
        assert!(match_pattern("f?o", "foo"));
        assert!(!match_pattern("f?o", "fooo"));
        assert!(match_pattern("LC_*", "LC_CTYPE"));
    }
    #[test]
    fn test_accept_env_pair() {
        assert!(accept_env_pair("TERM=xterm"));
        assert!(accept_env_pair("LANG=en_US"));
        assert!(accept_env_pair("LC_CTYPE=en"));
        assert!(!accept_env_pair("PATH=/bin"));
    }
}
