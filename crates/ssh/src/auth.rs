//! SSH grant checking — ports Go's `ssh/tailssh/tailssh.go` policy evaluation.

use chrono::Utc;
use rustscale_tailcfg::{Node, SSHAction, SSHPolicy, SSHPrincipal, SSHRule, UserProfile};
use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum EvalResult {
    Accept {
        action: SSHAction,
        local_user: String,
        accept_env: Vec<String>,
    },
    RejectedUser,
    Rejected,
    NoPolicy,
}

#[derive(Debug, Clone)]
pub struct ConnInfo {
    pub ssh_user: String,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub node: Node,
    pub user_profile: UserProfile,
}

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
            Err(MatchError::UserMatch) => failed_on_user = true,
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
enum MatchError {
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
    let local_user = if action.Reject {
        String::new()
    } else {
        let lu = map_local_user(&rule.SSHUsers, &info.ssh_user);
        if lu.is_empty() {
            return Err(MatchError::UserMatch);
        }
        lu
    };
    Ok(MatchedRule {
        action: action.clone(),
        local_user,
        accept_env: rule.AcceptEnv.clone(),
    })
}

fn map_local_user(ssh_users: &BTreeMap<String, String>, req: &str) -> String {
    match ssh_users.get(req).or_else(|| ssh_users.get("*")) {
        Some(v) if v == "=" => req.to_string(),
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
    use rustscale_tailcfg::StableNodeID;
    fn make_info(ssh_user: &str, src_ip: &str) -> ConnInfo {
        ConnInfo {
            ssh_user: ssh_user.into(),
            src_ip: src_ip.parse().unwrap(),
            dst_ip: "100.64.0.1".parse().unwrap(),
            node: Node {
                ID: 1,
                StableID: StableNodeID::from("nodeA"),
                Key: NodePrivate::generate().public(),
                ..Default::default()
            },
            user_profile: UserProfile {
                ID: 1,
                LoginName: "alice@example.com".into(),
                DisplayName: "Alice".into(),
                ProfilePicURL: String::new(),
            },
        }
    }
    #[test]
    fn test_no_rules() {
        assert_eq!(
            eval_ssh_policy(
                &SSHPolicy { Rules: vec![] },
                &make_info("root", "100.64.0.2")
            ),
            EvalResult::Rejected
        );
    }
    #[test]
    fn test_accept_any() {
        let p = SSHPolicy {
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
        match eval_ssh_policy(&p, &make_info("alice", "100.64.0.2")) {
            EvalResult::Accept { local_user, .. } => assert_eq!(local_user, "alice"),
            _ => panic!("expected Accept"),
        }
    }
    #[test]
    fn test_reject_user() {
        let p = SSHPolicy {
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
        assert_eq!(
            eval_ssh_policy(&p, &make_info("alice", "100.64.0.2")),
            EvalResult::RejectedUser
        );
    }
    #[test]
    fn test_principal_node_ip() {
        let p = SSHPolicy {
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
        match eval_ssh_policy(&p, &make_info("root", "100.64.0.2")) {
            EvalResult::Accept { local_user, .. } => assert_eq!(local_user, "root"),
            _ => panic!("expected Accept"),
        }
    }
    #[test]
    fn test_principal_user_login() {
        let p = SSHPolicy {
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
        match eval_ssh_policy(&p, &make_info("alice", "100.64.0.2")) {
            EvalResult::Accept { local_user, .. } => assert_eq!(local_user, "alice"),
            _ => panic!("expected Accept"),
        }
    }
    #[test]
    fn test_map_local_user() {
        let mut m = BTreeMap::new();
        m.insert("*".into(), "=".into());
        assert_eq!(map_local_user(&m, "bob"), "bob");
        m.insert("root".into(), "root".into());
        assert_eq!(map_local_user(&m, "root"), "root");
        assert_eq!(map_local_user(&BTreeMap::new(), "x"), "");
    }
}
