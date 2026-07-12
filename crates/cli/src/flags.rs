//! Minimal flag-parsing helpers for the CLI subcommands. No clap — just
//! hand-rolled loops matching the repo style (`crates/rustscaled/src/main.rs`).

/// A parsed boolean flag that can be set to `true` by passing `--name`
/// or `--name=true` / `--name=false`.
pub fn parse_bool_flag(args: &[String], name: &str) -> Option<bool> {
    let dash_name = format!("--{name}");
    let eq_prefix = format!("--{name}=");
    for arg in args {
        if arg == &dash_name {
            return Some(true);
        }
        if let Some(rest) = arg.strip_prefix(&eq_prefix) {
            return Some(rest == "true" || rest == "1");
        }
    }
    None
}

/// A parsed string flag that takes a value: `--name value` or `--name=value`.
#[allow(dead_code)]
pub fn parse_str_flag(args: &[String], name: &str) -> Option<String> {
    let dash_name = format!("--{name}");
    let eq_prefix = format!("--{name}=");
    for (i, arg) in args.iter().enumerate() {
        if arg == &dash_name {
            if let Some(val) = args.get(i + 1) {
                return Some(val.clone());
            }
        }
        if let Some(rest) = arg.strip_prefix(&eq_prefix) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Return the positional (non-flag) arguments from the given arg list.
#[allow(dead_code)]
pub fn positional_args(args: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        // Check if it's a known flag that takes a value (skip the value).
        if arg.starts_with("--") && !arg.contains('=') {
            // Check if next arg is the value for this flag.
            // Heuristic: if the flag name doesn't start with "--" in the
            // next position, treat it as a value and skip.
            // For bool flags (no value), we just skip the flag itself.
            // For str flags, the caller already consumed them via parse_*.
            i += 1;
        } else {
            result.push(arg.clone());
            i += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bool_flag() {
        let args = vec!["--json".to_string(), "--peers=false".to_string()];
        assert_eq!(parse_bool_flag(&args, "json"), Some(true));
        assert_eq!(parse_bool_flag(&args, "peers"), Some(false));
        assert_eq!(parse_bool_flag(&args, "active"), None);
    }

    #[test]
    fn test_parse_bool_flag_true_explicit() {
        let args = vec!["--active=true".to_string()];
        assert_eq!(parse_bool_flag(&args, "active"), Some(true));
    }

    #[test]
    fn test_parse_str_flag() {
        let args = vec!["--socket".to_string(), "/tmp/test.sock".to_string()];
        assert_eq!(
            parse_str_flag(&args, "socket"),
            Some("/tmp/test.sock".to_string())
        );
    }

    #[test]
    fn test_parse_str_flag_equals() {
        let args = vec!["--socket=/tmp/test.sock".to_string()];
        assert_eq!(
            parse_str_flag(&args, "socket"),
            Some("/tmp/test.sock".to_string())
        );
    }

    #[test]
    fn test_positional_args() {
        let args = vec![
            "100.64.0.2".to_string(),
            "--json".to_string(),
            "peer1".to_string(),
        ];
        let pos = positional_args(&args);
        assert_eq!(pos, vec!["100.64.0.2", "peer1"]);
    }
}
