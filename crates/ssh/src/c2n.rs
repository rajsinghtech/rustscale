//! C2N SSH commands — ports Go's `ssh/tailssh/c2n.go`.
//!
//! Provides the `/ssh/usernames` C2N endpoint that returns the list of
//! potential SSH user targets on this node. Used by the Tailscale admin
//! console for SSH connection autocompletion.

use serde::{Deserialize, Serialize};

/// Request body for the `/ssh/usernames` C2N endpoint.
/// Mirrors Go's `tailcfg.C2NSSHUsernamesRequest`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct C2nSshUsernamesRequest {
    #[serde(default)]
    pub Max: usize,
    #[serde(default)]
    pub Exclude: Vec<String>,
}

/// Response body for the `/ssh/usernames` C2N endpoint.
/// Mirrors Go's `tailcfg.C2NSSHUsernamesResponse`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct C2nSshUsernamesResponse {
    #[serde(default)]
    pub Usernames: Vec<String>,
}

/// Get the list of potential SSH usernames on this system.
///
/// On Unix systems, reads `/etc/passwd` for users with real shells.
/// On macOS, uses `dscl` to list users. Filters out system users
/// (names starting with `_`) and users with nologin/false shells.
pub fn get_ssh_usernames(req: &C2nSshUsernamesRequest) -> C2nSshUsernamesResponse {
    let max = if req.Max > 0 { req.Max } else { 10 };
    let exclude: Vec<String> = req.Exclude.iter().map(|s| s.to_lowercase()).collect();
    let mut usernames = Vec::new();

    let add = |u: &str, usernames: &mut Vec<String>| {
        let u = u.trim();
        if u.is_empty() || u.starts_with('_') {
            return;
        }
        if matches!(u, "nobody" | "daemon" | "sync") {
            return;
        }
        if exclude.iter().any(|e| e == u.to_lowercase()) {
            return;
        }
        if usernames.contains(&u.to_string()) {
            return;
        }
        if usernames.len() >= max {
            return;
        }
        usernames.push(u.to_string());
    };

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("dscl")
            .args([".", "list", "/Users"])
            .output()
        {
            for line in output.stdout.split(|&b| b == b'\n') {
                let line = std::str::from_utf8(line).unwrap_or("").trim();
                if !line.is_empty() && !line.starts_with('_') {
                    add(line, &mut usernames);
                }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('_') {
                    continue;
                }
                if line.ends_with("/nologin") || line.ends_with("/false") {
                    continue;
                }
                if let Some((username, _)) = line.split_once(':') {
                    add(username, &mut usernames);
                }
            }
        }
    }

    C2nSshUsernamesResponse { Usernames: usernames }
}

/// Handle a C2N SSH usernames request. Returns the JSON response body.
pub fn handle_c2n_ssh_usernames(body: &[u8]) -> Vec<u8> {
    let req: C2nSshUsernamesRequest = if body.is_empty() {
        C2nSshUsernamesRequest::default()
    } else {
        serde_json::from_slice(body).unwrap_or_default()
    };
    let resp = get_ssh_usernames(&req);
    serde_json::to_vec(&resp).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ssh_usernames_respects_max() {
        let req = C2nSshUsernamesRequest {
            Max: 3,
            Exclude: vec![],
        };
        let resp = get_ssh_usernames(&req);
        assert!(resp.Usernames.len() <= 3);
    }

    #[test]
    fn test_get_ssh_usernames_excludes() {
        let req = C2nSshUsernamesRequest {
            Max: 0,
            Exclude: vec!["root".into()],
        };
        let resp = get_ssh_usernames(&req);
        assert!(!resp.Usernames.contains(&"root".to_string()));
    }
}
