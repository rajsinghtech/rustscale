//! C2N SSH commands — ports Go's `ssh/tailssh/c2n.go`.
#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct C2nSshUsernamesRequest {
    #[serde(default)]
    pub Max: usize,
    #[serde(default)]
    pub Exclude: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct C2nSshUsernamesResponse {
    #[serde(default)]
    pub Usernames: Vec<String>,
}

pub fn get_ssh_usernames(req: &C2nSshUsernamesRequest) -> C2nSshUsernamesResponse {
    let max = if req.Max > 0 { req.Max } else { 10 };
    let exclude: Vec<String> = req.Exclude.iter().map(|s| s.to_lowercase()).collect();
    let mut usernames = Vec::new();

    let add = |u: &str, usernames: &mut Vec<String>| {
        let u = u.trim();
        if u.is_empty() || u.starts_with('_') { return; }
        if matches!(u, "nobody" | "daemon" | "sync") { return; }
        if exclude.iter().any(|e| *e == u.to_lowercase()) { return; }
        if usernames.contains(&u.to_string()) { return; }
        if usernames.len() >= max { return; }
        usernames.push(u.to_string());
    };

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("dscl").args([".", "list", "/Users"]).output() {
            for line in output.stdout.split(|&b| b == b'\n') {
                let line = std::str::from_utf8(line).unwrap_or("").trim();
                if !line.is_empty() && !line.starts_with('_') { add(line, &mut usernames); }
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('_') { continue; }
                if line.ends_with("/nologin") || line.ends_with("/false") { continue; }
                if let Some((username, _)) = line.split_once(':') { add(username, &mut usernames); }
            }
        }
    }

    C2nSshUsernamesResponse { Usernames: usernames }
}

pub fn handle_c2n_ssh_usernames(body: &[u8]) -> Vec<u8> {
    let req: C2nSshUsernamesRequest = if body.is_empty() { C2nSshUsernamesRequest::default() } else { serde_json::from_slice(body).unwrap_or_default() };
    let resp = get_ssh_usernames(&req);
    serde_json::to_vec(&resp).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_respects_max() {
        let resp = get_ssh_usernames(&C2nSshUsernamesRequest { Max: 3, Exclude: vec![] });
        assert!(resp.Usernames.len() <= 3);
    }
    #[test]
    fn test_excludes() {
        let resp = get_ssh_usernames(&C2nSshUsernamesRequest { Max: 0, Exclude: vec!["root".into()] });
        assert!(!resp.Usernames.contains(&"root".to_string()));
    }
}
