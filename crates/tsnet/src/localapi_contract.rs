//! Declarative LocalAPI route and schema contract.
//!
//! Request admission and the offline compatibility generator consume this
//! same table, so a route cannot silently disappear from the checked local
//! denominator while remaining dispatchable.

/// One admitted LocalAPI method/path with stable schema identifiers.
///
/// Schema names identify the intended wire model. They do not assert that
/// every optional upstream field is populated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalApiRouteContract {
    pub(crate) method: &'static str,
    pub(crate) endpoint: &'static str,
    pub(crate) request_schema: &'static str,
    pub(crate) response_schema: &'static str,
}

macro_rules! localapi_contract {
    ($method:literal, $endpoint:literal, $request:literal, $response:literal) => {
        LocalApiRouteContract {
            method: $method,
            endpoint: $endpoint,
            request_schema: $request,
            response_schema: $response,
        }
    };
}

pub(crate) const LOCALAPI_ROUTE_CONTRACTS: &[LocalApiRouteContract] = &[
    localapi_contract!("GET", "/", "none", "localapi.RouteIndex"),
    localapi_contract!("GET", "status", "none", "ipnstate.Status"),
    localapi_contract!(
        "GET",
        "whois",
        "localapi.WhoIsQuery",
        "apitype.WhoIsResponse"
    ),
    localapi_contract!("GET", "prefs", "none", "ipn.Prefs"),
    localapi_contract!("PATCH", "prefs", "ipn.MaskedPrefs", "ipn.Prefs"),
    localapi_contract!("POST", "start", "ipn.Options", "none"),
    localapi_contract!("POST", "login-interactive", "none", "none"),
    localapi_contract!("POST", "logout", "none", "none"),
    localapi_contract!("GET", "tka/status", "none", "tka.Status"),
    localapi_contract!("POST", "tka/init", "tka.InitRequest", "tka.InitResponse"),
    localapi_contract!("POST", "tka/init/ack", "tka.InitAckRequest", "none"),
    localapi_contract!("POST", "tka/sign", "tka.SignRequest", "none"),
    localapi_contract!("POST", "tka/disable", "tka.DisableRequest", "none"),
    localapi_contract!(
        "POST",
        "tka/force-local-disable",
        "tka.ForceLocalDisableRequest",
        "none"
    ),
    localapi_contract!("GET", "netmap", "none", "tailcfg.NetMap"),
    localapi_contract!(
        "POST",
        "routecheck",
        "routecheck.Query",
        "routecheck.Report"
    ),
    localapi_contract!("GET", "metrics", "none", "prometheus.Text"),
    localapi_contract!("GET", "health", "none", "health.Warning[]"),
    localapi_contract!("POST", "ping", "localapi.PingQuery", "tailcfg.PingResult"),
    localapi_contract!("POST", "debug-capture", "none", "capture.PcapStream"),
    localapi_contract!(
        "GET",
        "watch-ipn-bus",
        "localapi.WatchQuery",
        "ipn.NotifyStream"
    ),
    localapi_contract!("GET", "serve-config", "none", "ipn.ServeConfig"),
    localapi_contract!("POST", "serve-config", "ipn.ServeConfig", "none"),
    localapi_contract!("GET", "drive/status", "none", "drive.DriveStatus"),
    localapi_contract!("GET", "drive/config", "none", "drive.DriveConfig"),
    localapi_contract!(
        "PUT",
        "drive/config",
        "drive.DriveConfig",
        "drive.DriveStatus"
    ),
    localapi_contract!("GET", "profiles", "none", "ipn.LoginProfile[]"),
    localapi_contract!("PUT", "profiles", "none", "ipn.LoginProfile"),
    localapi_contract!("GET", "file-targets", "none", "tsnet.FileTarget[]"),
    localapi_contract!("GET", "debug", "localapi.DebugQuery", "json.Value"),
    localapi_contract!("POST", "debug", "localapi.DebugAction", "json.Value"),
    localapi_contract!("POST", "dial", "tsdial.Request", "tsdial.Stream"),
    localapi_contract!(
        "GET",
        "dns-query",
        "apitype.DNSQueryRequest",
        "apitype.DNSQueryResponse"
    ),
    localapi_contract!(
        "GET",
        "check-ip-forwarding",
        "none",
        "apitype.CheckIPForwardingResponse"
    ),
    localapi_contract!(
        "POST",
        "check-prefs",
        "ipn.MaskedPrefs",
        "localapi.CheckPrefsResponse"
    ),
    localapi_contract!(
        "POST",
        "set-expiry-sooner",
        "apitype.SetExpirySoonerRequest",
        "none"
    ),
    localapi_contract!("POST", "shutdown", "none", "none"),
    localapi_contract!(
        "GET",
        "id-token",
        "apitype.IDTokenRequest",
        "apitype.IDTokenResponse"
    ),
    localapi_contract!("POST", "reload-config", "none", "none"),
    localapi_contract!("GET", "cert/<domain>", "localapi.CertQuery", "pem.KeyPair"),
    localapi_contract!("GET", "profiles/<id>", "none", "ipn.LoginProfile"),
    localapi_contract!("POST", "profiles/<id>", "none", "none"),
    localapi_contract!("DELETE", "profiles/<id>", "none", "none"),
    localapi_contract!(
        "GET",
        "files[/<name>]",
        "localapi.FilesQuery",
        "ipn.WaitingFile[]|bytes"
    ),
    localapi_contract!("DELETE", "files[/<name>]", "none", "none"),
    localapi_contract!("PUT", "file-put/<stable-id>/<filename>", "bytes", "none"),
];

fn path_matches(pattern: &str, endpoint: &str) -> bool {
    match pattern {
        "cert/<domain>" => endpoint.starts_with("cert/"),
        "profiles/<id>" => endpoint.starts_with("profiles/"),
        "files[/<name>]" => endpoint == "files" || endpoint.starts_with("files/"),
        "file-put/<stable-id>/<filename>" => endpoint.starts_with("file-put/"),
        _ => endpoint == pattern,
    }
}

pub(crate) fn known_localapi_route(method: &str, endpoint: &str) -> bool {
    LOCALAPI_ROUTE_CONTRACTS.iter().any(|route| {
        debug_assert!(!route.request_schema.is_empty() && !route.response_schema.is_empty());
        route.endpoint != "/" && route.method == method && path_matches(route.endpoint, endpoint)
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn route_contract_ids_are_unique_and_schema_identifiers_are_nonempty() {
        let mut ids = BTreeSet::new();
        for route in LOCALAPI_ROUTE_CONTRACTS {
            assert!(ids.insert((route.method, route.endpoint)));
            assert!(!route.request_schema.is_empty());
            assert!(!route.response_schema.is_empty());
        }
    }

    #[test]
    fn admission_uses_exact_methods_and_declared_dynamic_paths() {
        assert!(known_localapi_route("GET", "status"));
        assert!(!known_localapi_route("POST", "status"));
        assert!(known_localapi_route("GET", "cert/node.example.ts.net"));
        assert!(known_localapi_route("DELETE", "files"));
        assert!(known_localapi_route("DELETE", "files/report.txt"));
        assert!(known_localapi_route("PUT", "file-put/node-1/report.txt"));
    }
}
