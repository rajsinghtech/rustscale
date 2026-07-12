//! Conn25 — peer connector selection and split-DNS resolver map.
//!
//! Ports Go's `appc/conn25.go`. The Conn25 API provides:
//! - [`pick_connector`]: select peers that match an app connector's tags
//! - [`app_dns_routes`]: build a split-DNS resolver map from the node's
//!   CapMap for the `tailscale-app://` scheme

use std::collections::BTreeMap;

use rustscale_tailcfg::{
    AppConnectorAttr, Node, NodeCapMap, NodeCapability, OptBool, Resolver,
    APP_CONNECTORS_EXPERIMENTAL_ATTR_NAME, DNS_ADDR_SCHEME,
};

/// Check whether a peer is an eligible app connector: its Hostinfo must be
/// valid and `AppConnector` must be set to true. Ports Go's
/// `isPeerEligibleConnector`.
pub fn is_peer_eligible_connector(peer: &Node) -> bool {
    let Some(hi) = &peer.Hostinfo else {
        return false;
    };
    hi.AppConnector == OptBool::True
}

/// Select peers that match the given app connector attributes, sorted by
/// preference (node ID). Ports Go's `PickConnector`.
///
/// Returns references to matching peers. A peer matches if:
/// 1. It is an eligible connector ([`is_peer_eligible_connector`])
/// 2. It has at least one tag that matches the app's connector set
pub fn pick_connector(peers: &[Node], app: &Conn25AttrInput) -> Vec<usize> {
    let app_tags_set: std::collections::HashSet<&str> = app
        .connectors
        .iter()
        .map(std::string::String::as_str)
        .collect();

    let mut matches: Vec<usize> = peers
        .iter()
        .enumerate()
        .filter(|(_, n)| {
            if !is_peer_eligible_connector(n) {
                return false;
            }
            n.Tags.iter().any(|t| app_tags_set.contains(t.as_str()))
        })
        .map(|(i, _)| i)
        .collect();

    // Sort by node ID for consistent ordering (matches Go's sortByPreference).
    matches.sort_by_key(|&i| peers[i].ID);
    matches
}

/// Input for [`pick_connector`] — the connector selection criteria from
/// `Conn25Attr`.
pub struct Conn25AttrInput {
    /// Connector tags (`"*"` or `tag:<tag-name>`).
    pub connectors: Vec<String>,
}

/// Build a split-DNS resolver map from the node's CapMap for the
/// `tailscale-app://` scheme. Ports Go's `AppDNSRoutes`.
///
/// Returns a map of domain → resolver list, where each resolver address is
/// `tailscale-app:<app_name>`. Returns an empty map if the node lacks the
/// app-connectors capability.
pub fn app_dns_routes(
    has_cap: impl Fn(&NodeCapability) -> bool,
    self_node: &Node,
) -> BTreeMap<String, Vec<Resolver>> {
    if !has_cap(&APP_CONNECTORS_EXPERIMENTAL_ATTR_NAME.to_string()) {
        return BTreeMap::new();
    }

    let apps = match unmarshal_app_connector_attrs(&self_node.CapMap) {
        Some(v) => v,
        None => return BTreeMap::new(),
    };

    // Map domain → app name (last write wins for duplicate domains).
    let mut app_names_by_domain: BTreeMap<String, String> = BTreeMap::new();
    for app in &apps {
        for domain in &app.Domains {
            let domain = domain.strip_prefix("*.").unwrap_or(domain);
            let domain = domain.to_lowercase();
            app_names_by_domain.insert(domain, app.Name.clone());
        }
    }

    let mut m = BTreeMap::new();
    for (domain, app_name) in app_names_by_domain {
        m.insert(
            domain,
            vec![Resolver {
                Addr: format!("{DNS_ADDR_SCHEME}:{app_name}"),
            }],
        );
    }
    m
}

/// Unmarshal `AppConnectorAttr` values from the node's CapMap under the
/// app-connectors-experimental key.
fn unmarshal_app_connector_attrs(cap_map: &NodeCapMap) -> Option<Vec<AppConnectorAttr>> {
    let raw_values = cap_map.get(APP_CONNECTORS_EXPERIMENTAL_ATTR_NAME)?;
    let mut attrs = Vec::new();
    for raw in raw_values {
        if raw.0.is_empty() {
            // null value — skip
            continue;
        }
        // Each value is a JSON-encoded AppConnectorAttr.
        let attr: AppConnectorAttr = serde_json::from_str(&raw.0).ok()?;
        attrs.push(attr);
    }
    if attrs.is_empty() {
        None
    } else {
        Some(attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::NodePrivate;
    use rustscale_tailcfg::{Hostinfo, NodeCapMap, RawMessage};

    fn make_connector_node(tags: Vec<String>, id: i64) -> Node {
        Node {
            ID: id,
            Key: NodePrivate::generate().public(),
            Tags: tags,
            Hostinfo: Some(Hostinfo {
                AppConnector: OptBool::True,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_non_connector_node(id: i64) -> Node {
        Node {
            ID: id,
            Key: NodePrivate::generate().public(),
            Hostinfo: Some(Hostinfo {
                AppConnector: OptBool::False,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn is_peer_eligible_connector_true() {
        let n = make_connector_node(vec!["tag:prod".into()], 1);
        assert!(is_peer_eligible_connector(&n));
    }

    #[test]
    fn is_peer_eligible_connector_false() {
        let n = make_non_connector_node(1);
        assert!(!is_peer_eligible_connector(&n));
    }

    #[test]
    fn is_peer_eligible_no_hostinfo() {
        let n = Node {
            ID: 1,
            Key: NodePrivate::generate().public(),
            Hostinfo: None,
            ..Default::default()
        };
        assert!(!is_peer_eligible_connector(&n));
    }

    #[test]
    fn pick_connector_matches_by_tag() {
        let peers = vec![
            make_connector_node(vec!["tag:prod".into()], 1),
            make_connector_node(vec!["tag:dev".into()], 2),
            make_non_connector_node(3),
        ];
        let app = Conn25AttrInput {
            connectors: vec!["tag:prod".into()],
        };
        let result = pick_connector(&peers, &app);
        assert_eq!(result, vec![0]);
    }

    #[test]
    fn pick_connector_matches_multiple() {
        let peers = vec![
            make_connector_node(vec!["tag:prod".into()], 3),
            make_connector_node(vec!["tag:dev".into()], 1),
            make_connector_node(vec!["tag:prod".into()], 2),
        ];
        let app = Conn25AttrInput {
            connectors: vec!["tag:prod".into()],
        };
        let result = pick_connector(&peers, &app);
        // Sorted by node ID: 2 (index 2), 0 (index 0)
        assert_eq!(result, vec![2, 0]);
    }

    #[test]
    fn pick_connector_no_match() {
        let peers = vec![
            make_connector_node(vec!["tag:prod".into()], 1),
            make_non_connector_node(2),
        ];
        let app = Conn25AttrInput {
            connectors: vec!["tag:nonexistent".into()],
        };
        let result = pick_connector(&peers, &app);
        assert!(result.is_empty());
    }

    #[test]
    fn app_dns_routes_builds_map() {
        let mut cap_map: NodeCapMap = BTreeMap::new();
        let attr = AppConnectorAttr {
            Name: "my-app".into(),
            Domains: vec!["example.com".into(), "*.corp.com".into()],
            ..Default::default()
        };
        let attr_json = serde_json::to_string(&attr).unwrap();
        cap_map.insert(
            APP_CONNECTORS_EXPERIMENTAL_ATTR_NAME.to_string(),
            vec![RawMessage(attr_json)],
        );

        let self_node = Node {
            ID: 1,
            Key: NodePrivate::generate().public(),
            CapMap: cap_map,
            ..Default::default()
        };

        let routes = app_dns_routes(
            |cap| cap == APP_CONNECTORS_EXPERIMENTAL_ATTR_NAME,
            &self_node,
        );

        assert_eq!(routes.len(), 2);
        assert_eq!(
            routes.get("example.com").unwrap()[0].Addr,
            "tailscale-app:my-app"
        );
        assert_eq!(
            routes.get("corp.com").unwrap()[0].Addr,
            "tailscale-app:my-app"
        );
    }

    #[test]
    fn app_dns_routes_no_capability_returns_empty() {
        let self_node = Node {
            ID: 1,
            Key: NodePrivate::generate().public(),
            ..Default::default()
        };
        let routes = app_dns_routes(|_| false, &self_node);
        assert!(routes.is_empty());
    }

    #[test]
    fn app_dns_routes_multiple_apps_last_wins() {
        let mut cap_map: NodeCapMap = BTreeMap::new();
        let attr1 = AppConnectorAttr {
            Name: "app1".into(),
            Domains: vec!["shared.com".into()],
            ..Default::default()
        };
        let attr2 = AppConnectorAttr {
            Name: "app2".into(),
            Domains: vec!["shared.com".into()],
            ..Default::default()
        };
        cap_map.insert(
            APP_CONNECTORS_EXPERIMENTAL_ATTR_NAME.to_string(),
            vec![
                RawMessage(serde_json::to_string(&attr1).unwrap()),
                RawMessage(serde_json::to_string(&attr2).unwrap()),
            ],
        );

        let self_node = Node {
            ID: 1,
            Key: NodePrivate::generate().public(),
            CapMap: cap_map,
            ..Default::default()
        };

        let routes = app_dns_routes(
            |cap| cap == APP_CONNECTORS_EXPERIMENTAL_ATTR_NAME,
            &self_node,
        );

        // Last write wins for duplicate domains.
        assert_eq!(
            routes.get("shared.com").unwrap()[0].Addr,
            "tailscale-app:app2"
        );
    }
}
