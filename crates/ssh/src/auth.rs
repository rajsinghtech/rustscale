//! SSH grant checking — ports the policy evaluation logic from Go's
//! `ssh/tailssh/tailssh.go` (`evalSSHPolicy`, `matchRule`,
//! `anyPrincipalMatches`, `mapLocalUser`).
//!
//! When an SSH connection arrives, the server:
//! 1. Resolves the connecting peer's Tailscale identity (node + user profile)
//!    via WhoIs.
//! 2. Evaluates the SSHPolicy from the netmap against the peer's identity
//!    and the requested SSH user.
//! 3. The first matching rule's action (accept/reject/holdAndDelegate)
//!    determines the outcome.

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::Utc;

use rustscale_tailcfg::{
    Node, SSHAction, SSHPrincipal, SSHRule, SSHPolicy, StableNodeID, UserProfile,
};

/// Result of evaluating the SSH policy for a connection.
#[derive(Debug, Clone, PartialEq)]
pub enum EvalResult {
    /// Connection accepted with the given action and local user.
    Accept {
        action: SSHAction,
        local_user: String,
        accept_env: Vec<String>,
    },
    /// Connection rejected because the SSH user doesn't match any rule.
    RejectedUser,
    /// Connection rejected for other reasons.
    Rejected,
    /// No SSH policy is configured.
    NoPolicy,
}

/// Connection info used for policy evaluation. Mirrors Go's `sshConnInfo`.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    /// The requested SSH username (e.g. "root", "alice").
    pub ssh_user: String,
    /// Source Tailscale IP.
    pub src_ip: IpAddr,
    /// Destination Tailscale IP.
    pub dst_ip: IpAddr,
    /// The connecting peer's node.
    pub node: Node,
    /// The connecting peer's user profile.
    pub user_profile: UserProfile,
}

/// Evaluate the SSH policy against a connection.
///
/// Returns the first matching rule's action and the mapped local user.
/// If no rule matches, returns `Rejected` or `RejectedUser`.
pub fn eval_ssh_policy(policy: &SSHPolicy, info: &ConnInfo) -> EvalResult {
    let mut failed_on_user = false;

    for rule in &policy.Rules {
        match match_rule(rule, info) {
            Ok(MatchedRule {
                action,
                local_user,
                accept_env,
            }) => {
                return EvalResult::Accept {
                    action,
                    local_user,
                    accept_env,
                };
            }
            Err(MatchError::UserMatch) => {
                failed_on_user = true;
            }
            Err(_) => {}
        }
    }

    if failed_on_user {
        EvalResult::RejectedUser
    } else {
        EvalResult::Rejected
    }
}

struct MatchedRule {
    action: SSHAction,
    local_user: String,
    accept_env: Vec<String>,
}

#[derive(Debug)]
enum MatchError {
    NilRule,
    NilAction,
    RuleExpired,
    PrincipalMatch,
    UserMatch,
}

fn match_rule(rule: &SSHRule, info: &ConnInfo) -> Result<MatchedRule, MatchError> {
    let action = rule.Action.as_ref().ok_or(MatchError::NilAction)?;

    if let Some(expiry) = &rule.RuleExpires {
        if expiry < &Utc::now() {
            return Err(MatchError::RuleExpired);
        }
    }

    if !any_principal_matches(&rule.Principals, info) {
        return Err(MatchError::PrincipalMatch);
    }

    let local_user = if !action.Reject {
        let lu = map_local_user(&rule.SSHUsers, &info.ssh_user);
        if lu.is_empty() {
            return Err(MatchError::UserMatch);
        }
        lu
    } else {
        String::new()
    };

    Ok(MatchedRule {
        action: action.clone(),
        local_user,
        accept_env: rule.AcceptEnv.clone(),
    })
}

/// Map an SSH user to a local user using the rule's SSHUsers map.
/// If the map contains the exact ssh_user, use that value.
/// Otherwise, fall back to the "*" wildcard.
/// If the value is "=", map directly to the requested ssh_user.
fn map_local_user(ssh_users: &BTreeMap<String, String>, req_ssh_user: &str) -> String {
    let v = ssh_users.get(req_ssh_user).or_else(|| ssh_users.get("*"));
    match v {
        Some(v) if v == "=" => req_ssh_user.to_string(),
        Some(v) => v.clone(),
        None => String::new(),
    }
}

fn any_principal_matches(principals: &[SSHPrincipal], info: &ConnInfo) -> bool {
    principals.iter().any(|p| principal_matches(p, info))
}

fn principal_matches(p: &SSHPrincipal, info: &ConnInfo) -> bool {
    if p.Any {
        return true;
    }

    if !p.Node.is_empty() && p.Node == info.node.StableID {
        return true;
    }

    if !p.NodeIP.is_empty() {
        if let Ok(ip) = p.NodeIP.parse::<IpAddr>() {
            if ip == info.src_ip {
                return true;
            }
        }
    }

    if !p.UserLogin.is_empty() && info.user_profile.LoginName == p.UserLogin {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::NodePrivate;

    fn make_conn_info(ssh_user: &str, src_ip: &str, node: Node) -> ConnInfo {
        ConnInfo {
            ssh_user: ssh_user.into(),
            src_ip: src_ip.parse().unwrap(),
            dst_ip: "100.64.0.1".parse().unwrap(),
            node,
            user_profile: UserProfile {
                ID: 1,
                LoginName: "alice@example.com".into(),
                DisplayName: "Alice".into(),
                ProfilePicURL: String::new(),
            },
        }
    }

    fn make_node(id: &str, stable_id: &str) -> Node {
        Node {
            ID: 1,
            StableID: StableNodeID::from(stable_id),
            Name: "node.tailnet.ts.net.".into(),
            User: 1,
            Key: NodePrivate::generate().public(),
            Addresses: vec![format!("100.64.0.2/32")],
            ..Default::default()
        }
    }

    #[test]
    fn test_no_policy() {
        let policy = SSHPolicy { Rules: vec![] };
        let info = make_conn_info("root", "100.64.0.2", make_node("1", "nodeA"));
        let result = eval_ssh_policy(&policy, &info);
        assert_eq!(result, EvalResult::Rejected);
    }

    #[test]
    fn test_accept_any_principal() {
        let policy = SSHPolicy {
            Rules: vec![SSHRule {
                Principals: vec![SSHPrincipal {
                    Any: true,
                    ..Default::default()
                }],
                SSHUsers: {
                    let mut m = BTreeMap::new();
                    m.insert("*".into(), "=".into());
                    m
                },
                Action: Some(SSHAction {
                    Accept: true,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        let info = make_conn_info("alice", "100.64.0.2", make_node("1", "nodeA"));
        let result = eval_ssh_policy(&policy, &info);
        match result {
            EvalResult::Accept { local_user, .. } => assert_eq!(local_user, "alice"),
            _ => panic!("expected Accept"),
        }
    }

    #[test]
    fn test_reject_by_user() {
        let policy = SSHPolicy {
            Rules: vec![SSHRule {
                Principals: vec![SSHPrincipal {
                    Any: true,
                    ..Default::default()
                }],
                SSHUsers: {
                    let mut m = BTreeMap::new();
                    m.insert("root".into(), "root".into());
                    m
                },
                Action: Some(SSHAction {
                    Accept: true,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        let info = make_conn_info("alice", "100.64.0.2", make_node("1", "nodeA"));
        let result = eval_ssh_policy(&policy, &info);
        assert_eq!(result, EvalResult::RejectedUser);
    }

    #[test]
    fn test_principal_node_ip_match() {
        let policy = SSHPolicy {
            Rules: vec![SSHRule {
                Principals: vec![SSHPrincipal {
                    NodeIP: "100.64.0.2".into(),
                    ..Default::default()
                }],
                SSHUsers: {
                    let mut m = BTreeMap::new();
                    m.insert("*".into(), "root".into());
                    m
                },
                Action: Some(SSHAction {
                    Accept: true,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        let info = make_conn_info("root", "100.64.0.2", make_node("1", "nodeA"));
        match eval_ssh_policy(&policy, &info) {
            EvalResult::Accept { local_user, .. } => assert_eq!(local_user, "root"),
            _ => panic!("expected Accept"),
        }
    }

    #[test]
    fn test_principal_user_login_match() {
        let policy = SSHPolicy {
            Rules: vec![SSHRule {
                Principals: vec![SSHPrincipal {
                    UserLogin: "alice@example.com".into(),
                    ..Default::default()
                }],
                SSHUsers: {
                    let mut m = BTreeMap::new();
                    m.insert("*".into(), "=".into());
                    m
                },
                Action: Some(SSHAction {
                    Accept: true,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        let info = make_conn_info("alice", "100.64.0.2", make_node("1", "nodeA"));
        match eval_ssh_policy(&policy, &info) {
            EvalResult::Accept { local_user, .. } => assert_eq!(local_user, "alice"),
            _ => panic!("expected Accept"),
        }
    }

    #[test]
    fn test_map_local_user_equal() {
        let mut m = BTreeMap::new();
        m.insert("*".into(), "=".into());
        assert_eq!(map_local_user(&m, "bob"), "bob");
    }

    #[test]
    fn test_map_local_user_specific() {
        let mut m = BTreeMap::new();
        m.insert("root".into(), "root".into());
        m.insert("*".into(), "nobody".into());
        assert_eq!(map_local_user(&m, "root"), "root");
        assert_eq!(map_local_user(&m, "alice"), "nobody");
    }

    #[test]
    fn test_map_local_user_no_match() {
        let m = BTreeMap::new();
        assert_eq!(map_local_user(&m, "root"), "");
    }
}
