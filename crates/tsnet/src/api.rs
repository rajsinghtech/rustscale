#[allow(clippy::wildcard_imports)]
use super::*;

impl Server {
    /// Get the current server status.
    pub fn status(&self) -> ServerStatus {
        let Some(ref inner) = self.inner else {
            return ServerStatus {
                up: false,
                tailscale_ips: vec![],
                peer_count: 0,
                peers: vec![],
                hostname: self.config.hostname.clone(),
                packet_drops: 0,
                health: vec![],
                key_expired: false,
            };
        };
        let peers: Vec<PeerInfo> = inner
            .peers
            .try_read()
            .map(|p| {
                p.iter()
                    .filter(|n| !n.Key.is_zero())
                    .map(|n| PeerInfo {
                        node_key: n.Key.clone(),
                        name: n.Name.clone(),
                        ips: extract_node_ips(n),
                        path_class: inner.magicsock.peer_path_class(&n.Key),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let packet_drops = inner
            .packet_drops
            .load(std::sync::atomic::Ordering::Relaxed);
        ServerStatus {
            up: true,
            tailscale_ips: inner.tailscale_ips.clone(),
            peer_count: peers.len(),
            peers,
            hostname: self.config.hostname.clone(),
            packet_drops,
            health: inner.health.current_warnings(),
            key_expired: inner.key_expired.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Listen for incoming TCP connections on `port` (netstack mode only).
    ///
    /// **Auto-starts** the server if it has not been started yet (calling
    /// [`Server::up`] internally). Returns an error in TUN mode — there is
    /// no in-process netstack to accept connections.
    ///
    /// Mirrors Go's `Server.Listen` which calls `Start()` first.
    pub async fn listen(&mut self, port: u16) -> Result<rustscale_netstack::Listener, TsnetError> {
        Box::pin(self.ensure_up()).await?;
        let inner = self.inner.as_ref().expect("ensure_up guarantees inner");
        match &inner.data_plane {
            DataPlane::Netstack(ns) => Ok(ns.listen(port).await?),
            DataPlane::Tun => Err(TsnetError::NotAvailableInTunMode),
        }
    }

    /// Listen for incoming TLS connections on `port` (netstack mode only).
    ///
    /// Attempts to use a Let's Encrypt certificate provisioned via the
    /// control plane ([`Server::control_cert_provider`]); on any error
    /// (HTTPS not enabled for the tailnet, ACME client unavailable, cache
    /// miss) it falls back to a self-signed per-node certificate with a
    /// warning. Call [`Server::control_cert_provider`] directly to observe
    /// the typed [`CertError`] when you need to distinguish the cases.
    ///
    /// Returns an error in TUN mode.
    pub async fn listen_tls(&self, port: u16) -> Result<TlsListener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let provider = match self.control_cert_provider().await {
            Ok(p) => {
                inner.health.set_healthy(WARN_CERT_FALLBACK);
                p
            }
            Err(e) => {
                eprintln!("tsnet: control cert unavailable ({e}); using self-signed");
                inner.health.set_unhealthy(
                    WARN_CERT_FALLBACK,
                    format!("serving self-signed fallback: {e}"),
                );
                tls::default_cert_provider(&inner.tailscale_ips)
            }
        };
        self.listen_tls_with_provider(port, provider).await
    }

    /// Build a Let's Encrypt-via-control [`CertProvider`] for this node's
    /// FQDN, fetching/caching the cert material. Returns a typed
    /// [`CertError`] when HTTPS certs are not enabled for the tailnet
    /// ([`CertError::NotEnabled`]) or the ACME order flow fails
    /// ([`CertError::Acme`]); callers can fall back to a self-signed cert
    /// in those cases.
    ///
    /// Requires the server to be up. The cert+key are cached in
    /// `state_dir` (`<fqdn>.crt.pem` / `<fqdn>.key.pem`) and refreshed when
    /// within 14 days of expiry. The ACME account key is persisted in
    /// `state_dir/acme-account.key.pem`.
    pub async fn control_cert_provider(&self) -> Result<Arc<dyn CertProvider>, CertError> {
        let inner = self
            .inner
            .as_ref()
            .ok_or_else(|| CertError::CacheInvalid(String::new(), "server not up".into()))?;
        let cert_domains = inner
            .dns_config
            .read()
            .await
            .as_ref()
            .map(|c| c.CertDomains.clone())
            .unwrap_or_default();
        let state_dir = self.config.state_dir.clone().unwrap_or_else(|| {
            let mut p = std::env::temp_dir();
            p.push("rustscale-certs");
            p
        });
        let _ = std::fs::create_dir_all(&state_dir);
        let fetcher = Arc::new(AcmeCertFetcher::new(
            cert_domains,
            state_dir.clone(),
            self.config.control_url.clone(),
            inner.machine_key.clone(),
            inner.server_pub_key.clone(),
            inner.node_key.clone(),
            CAPABILITY_VERSION,
            PROTOCOL_VERSION,
        ));
        let prov = Arc::new(
            ControlCertProvider::new(state_dir, &inner.our_fqdn, fetcher)
                .with_health(inner.health.clone()),
        );
        prov.refresh().await?;
        Ok(prov)
    }

    /// Listen for incoming TLS connections on `port` using a caller-supplied
    /// [`CertProvider`] (netstack mode only).
    ///
    /// This is the lower-level entry point behind [`Server::listen_tls`]; use
    /// it when you need a custom certificate source (e.g. pre-provisioned
    /// certs). Returns an error in TUN mode.
    pub async fn listen_tls_with_provider(
        &self,
        port: u16,
        provider: Arc<dyn CertProvider>,
    ) -> Result<TlsListener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        match &inner.data_plane {
            DataPlane::Netstack(ns) => {
                let listener = ns.listen(port).await?;
                TlsListener::new(listener, provider).map_err(TsnetError::Tls)
            }
            DataPlane::Tun => Err(TsnetError::NotAvailableInTunMode),
        }
    }

    /// Dial a remote `ip:port` or `hostname:port` (netstack mode only).
    ///
    /// **Auto-starts** the server if it has not been started yet (calling
    /// [`Server::up`] internally). Resolves tailnet hostnames via MagicDNS
    /// (short name, FQDN) and non-tailnet hostnames via the system resolver
    /// (requires an exit node for the traffic to reach the internet). Returns
    /// an error in TUN mode.
    ///
    /// Mirrors Go's `Server.Dial` which calls `Start()` first.
    pub async fn dial(&mut self, addr: &str) -> Result<NetstackStream, TsnetError> {
        Box::pin(self.ensure_up()).await?;
        let inner = self.inner.as_ref().expect("ensure_up guarantees inner");
        let socket_addr = resolve_addr(addr, inner).await?;
        match &inner.data_plane {
            DataPlane::Netstack(ns) => Ok(ns.dial(socket_addr).await?),
            DataPlane::Tun => Err(TsnetError::NotAvailableInTunMode),
        }
    }

    /// Listen for UDP datagrams on `addr` (netstack mode only).
    ///
    /// `addr` is `":port"`, `"ip:port"`, or `"hostname:port"`. An empty host
    /// binds to the node's primary tailnet IP; a hostname is resolved via
    /// MagicDNS. If port is 0, an ephemeral port (10002–19999) is allocated.
    /// Returns an error in TUN mode.
    pub async fn listen_packet(&self, addr: &str) -> Result<UdpListener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let netstack = match &inner.data_plane {
            DataPlane::Netstack(ns) => ns.clone(),
            DataPlane::Tun => return Err(TsnetError::NotAvailableInTunMode),
        };

        let (host, port_str) = addr
            .rsplit_once(':')
            .ok_or_else(|| TsnetError::Builder(format!("invalid address: {addr}")))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| TsnetError::Builder(format!("invalid port: {addr}")))?;

        let ip = if host.is_empty() {
            *inner
                .tailscale_ips
                .first()
                .ok_or_else(|| TsnetError::Builder("no tailnet IP assigned".into()))?
        } else if let Ok(ip) = host.parse::<IpAddr>() {
            ip
        } else {
            let r = inner.resolver.read().await;
            r.resolve_first(host)
                .ok_or_else(|| TsnetError::Builder(format!("cannot resolve: {host}")))?
        };

        Ok(netstack.listen_packet(ip, port).await?)
    }

    /// Start a local SOCKS5 proxy (RFC 1928) bound to `bind_addr` on the **OS**
    /// TCP stack (e.g. `"127.0.0.1:1080"`, `":1080"`, or `"1080"`). Each
    /// CONNECT request is dialed *through the tailnet* via [`Server::dial`]
    /// (resolving MagicDNS names and honoring the selected exit node).
    ///
    /// Only the no-auth method and the CONNECT command are supported; BIND and
    /// UDP-ASSOCIATE are rejected with command-not-supported. Address types
    /// IPv4, IPv6, and domain-name are accepted.
    ///
    /// The returned [`Socks5Handle`] exposes the bound address (useful for
    /// `:0`) and a graceful `stop`; the background task is also registered in
    /// the server's task set so [`Server::close`] aborts it. Requires netstack
    /// mode (returns [`TsnetError::NotAvailableInTunMode`] in TUN mode).
    ///
    /// C-representable: string in, handle + bound-port out (see FFI
    /// `ts_listen_socks5`).
    pub async fn listen_socks5(&self, bind_addr: &str) -> Result<Socks5Handle, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let netstack = match &inner.data_plane {
            DataPlane::Netstack(ns) => ns.clone(),
            DataPlane::Tun => return Err(TsnetError::NotAvailableInTunMode),
        };
        let dialer = ServerSocksDialer::new(netstack, inner.resolver.clone(), inner.peers.clone());
        let mut handle = socks5::spawn_socks5(bind_addr, dialer, None)
            .await
            .map_err(TsnetError::Io)?;
        // Register the task in the server's set so close() aborts it.
        if let Some(task) = handle.take_task() {
            inner.tasks.lock().await.push(task);
        }
        Ok(handle)
    }

    /// Look up which peer owns the route for a destination IP (longest-prefix
    /// match). Returns `None` if no route matches or the server is not up.
    ///
    /// This is the in-process routing table's view — it reflects the latest
    /// netmap peers and the `accept_routes` setting. Useful for testing
    /// subnet-route installation and for the FFI layer.
    pub fn route_lookup(&self, ip: IpAddr) -> Option<NodePublic> {
        let inner = self.inner.as_ref()?;
        let rt = inner.route_table.try_read().ok()?;
        rt.lookup(ip)
    }

    /// Snapshot of the current route table entries as `(cidr_string, peer_key)`
    /// pairs, sorted by longest prefix first. Useful for diagnostics and
    /// testing subnet-route installation.
    pub fn routes(&self) -> Vec<(String, NodePublic)> {
        let Some(inner) = self.inner.as_ref() else {
            return vec![];
        };
        let Ok(rt) = inner.route_table.try_read() else {
            return vec![];
        };
        rt.entries()
            .map(|(net, prefix, peer)| (format!("{net}/{prefix}"), peer.clone()))
            .collect()
    }

    /// Select an exit node by tailnet IP or MagicDNS hostname. After this,
    /// all non-tailnet traffic routes to the selected peer — in netstack mode
    /// via the in-process `RouteTable`, in TUN mode via the data pump (OS
    /// default-route overrides must be installed separately, see
    /// [`TunModeConfig::exit_node`]).
    ///
    /// `ip_or_name` may be a tailnet IP (e.g. `"100.64.0.5"`) or a MagicDNS
    /// hostname (e.g. `"peer"` or `"peer.tailnet.ts.net"`). The peer must be
    /// exit-node-capable (its `AllowedIPs` must contain `0.0.0.0/0`); otherwise
    /// returns [`TsnetError::NotExitCapable`]. Returns
    /// [`TsnetError::ExitNodeNotFound`] if no peer matches.
    ///
    /// In TUN mode, existing TCP connections are broken best-effort after the
    /// route change (mirroring Go's `breakTCPConns`), since the old routes no
    /// longer apply. This is **not** done in netstack mode — it would kill the
    /// process's own DERP/control TCP connections.
    ///
    /// C-representable: string in, error code out (see FFI `ts_set_exit_node`).
    pub async fn set_exit_node(&self, ip_or_name: &str) -> Result<(), TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let peers = inner.peers.read().await;
        let peer_key = resolve_exit_node(&peers, ip_or_name)?;
        drop(peers);
        inner.route_table.write().await.set_exit_node(peer_key);
        if matches!(inner.data_plane, DataPlane::Tun) {
            break_tcp_conns_best_effort();
        }
        Ok(())
    }

    /// Clear the selected exit node. After this, non-tailnet destinations no
    /// longer route through a peer (unless `accept_routes` installed them).
    ///
    /// In TUN mode, existing TCP connections are broken best-effort after the
    /// route change (mirroring Go's `breakTCPConns`), since the old routes no
    /// longer apply. This is **not** done in netstack mode — it would kill the
    /// process's own DERP/control TCP connections.
    ///
    /// C-representable: no args, error code out (see FFI `ts_clear_exit_node`).
    pub async fn clear_exit_node(&self) -> Result<(), TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        inner.route_table.write().await.clear_exit_node();
        if matches!(inner.data_plane, DataPlane::Tun) {
            break_tcp_conns_best_effort();
        }
        Ok(())
    }

    /// The currently selected exit node's peer key, if any.
    pub async fn exit_node(&self) -> Option<NodePublic> {
        let inner = self.inner.as_ref()?;
        let rt = inner.route_table.read().await;
        rt.exit_node().cloned()
    }

    /// Look up which peer owns a tailnet IP address ([WhoIs]). Returns the
    /// peer's MagicDNS name, tailscale IPs, and the owning user's login/
    /// display name (from `MapResponse.UserProfiles`).
    ///
    /// Returns `None` only if the server is not up; if the server is up but
    /// no peer matches, returns `Some(WhoIsInfo { found: false, .. })`.
    pub async fn whois(&self, remote_addr: IpAddr) -> Option<WhoIsInfo> {
        let inner = self.inner.as_ref()?;
        let peers = inner.peers.read().await;
        let ups = inner.user_profiles.read().await;
        Some(
            whois_lookup(&peers, &ups, remote_addr).unwrap_or_else(|| WhoIsInfo {
                found: false,
                node_name: String::new(),
                tailscale_ips: vec![],
                user_id: 0,
                login_name: String::new(),
                display_name: String::new(),
            }),
        )
    }

    /// Set the serve configuration. Starts netstack listeners on the
    /// configured tailnet ports and dispatches each connection to the matching
    /// handler (TCP forward, HTTP/HTTPS web, reverse proxy, static text).
    ///
    /// For configs with HTTPS or TLS-terminated TCP-forward handlers, a
    /// Let's Encrypt cert is provisioned via the control plane (falling back
    /// to self-signed on error). Returns the list of ports now being served.
    ///
    /// Requires the server to be up in netstack mode (not TUN mode).
    /// C-representable: the config is a plain serde struct; the FFI layer
    /// exposes a minimal `ts_serve_tcp` for the common TCP-forward case.
    pub async fn set_serve_config(&self, cfg: ServeConfig) -> Result<Vec<u16>, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let runner = inner
            .serve
            .as_ref()
            .ok_or(TsnetError::NotAvailableInTunMode)?;

        // If the config has HTTPS or TLS-terminated handlers, provision a cert.
        let needs_tls = cfg
            .TCP
            .values()
            .any(|h| h.HTTPS || !h.TerminateTLS.is_empty());
        let cert = if needs_tls {
            match self.control_cert_provider().await {
                Ok(p) => {
                    inner.health.set_healthy(WARN_CERT_FALLBACK);
                    Some(p)
                }
                Err(e) => {
                    eprintln!("tsnet: serve cert unavailable ({e}); using self-signed");
                    inner.health.set_unhealthy(
                        WARN_CERT_FALLBACK,
                        format!("serving self-signed fallback: {e}"),
                    );
                    Some(tls::default_cert_provider(&inner.tailscale_ips))
                }
            }
        } else {
            None
        };

        let started = runner.set_config(cfg, cert).await?;
        Ok(started)
    }

    /// Listen for incoming Funnel connections on `port` (443, 8443, or 10000).
    ///
    /// Validates that the node has the `funnel` node attribute from the
    /// netmap. On API-only tailnets where control never grants funnel, returns
    /// a typed [`FunnelError::NotEnabled`] — the expected clean error.
    ///
    /// Funnel ingress arrives via DERP-relayed connections from Tailscale's
    /// ingress servers; the node appears as a peer and no special transport
    /// is needed beyond accepting TLS conns on the port. The returned
    /// [`TlsListener`] terminates TLS with the control cert provider (or
    /// self-signed fallback).
    ///
    /// **What remains for full Funnel**: wiring the ingress peer's
    /// `Tailscale-Ingress-Target` header dispatch (Go's `handleServeIngress`)
    /// and advertising `Hostinfo.IngressEnabled` to control. The listener
    /// itself works — connections from the tailnet (and, when control grants
    /// the funnel attr, from the internet) are accepted and TLS-terminated.
    pub async fn listen_funnel(&self, port: u16) -> Result<TlsListener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let _runner = inner
            .serve
            .as_ref()
            .ok_or(TsnetError::NotAvailableInTunMode)?;

        // Validate the port is a funnel port.
        if !FUNNEL_PORTS.contains(&port) {
            return Err(TsnetError::Funnel(FunnelError::PortNotAllowed(port)));
        }

        // Check the node has the funnel capability from the netmap.
        // Use our own node from the netmap (MapResponse.Node is not retained
        // separately, so we check via the self node's capabilities). The self
        // node's capabilities come from the DNSConfig/cert domains (HTTPS) and
        // the node attributes delivered in the map stream.
        let self_node = self.self_node().await;
        check_funnel_access(port, &self_node)?;

        // Provision a cert (LE via control, self-signed fallback).
        let provider = match self.control_cert_provider().await {
            Ok(p) => {
                inner.health.set_healthy(WARN_CERT_FALLBACK);
                p
            }
            Err(e) => {
                eprintln!("tsnet: funnel cert unavailable ({e}); using self-signed");
                inner.health.set_unhealthy(
                    WARN_CERT_FALLBACK,
                    format!("serving self-signed fallback: {e}"),
                );
                tls::default_cert_provider(&inner.tailscale_ips)
            }
        };

        self.listen_tls_with_provider(port, provider).await
    }

    /// Listen for incoming connections addressed to a Tailscale VIP Service
    /// (netstack mode only).
    ///
    /// Resolves the service's VIP v4 addresses from the netmap (self node's
    /// `CapMap` under the `service-host` key), adds them to the userspace
    /// netstack interface, and listens on the specified `port` on each VIP.
    /// Connections addressed to the service's VIP IP on the port are accepted
    /// and surface as normal tsnet streams via [`ServiceListener::accept`].
    ///
    /// The service name must be of the form `svc:dns-label` (e.g.
    /// `"svc:my-service"`). The node must be tagged and the service must be
    /// approved by an admin or ACL auto-approval rules; otherwise the netmap
    /// will not carry VIP addresses for the service and this method returns
    /// [`ServiceError::NoVipAddrs`].
    ///
    /// # PROXY protocol v2
    ///
    /// When [`ServiceMode::with_proxy_protocol`]`(true)` is set, a PROXY
    /// protocol v2 binary header is prepended to each accepted stream so the
    /// backend learns the real client address. See
    /// <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustscale_tsnet::{Server, ServiceMode};
    /// # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut server = Server::builder()
    ///     .hostname("my-svc")
    ///     .auth_key("tskey-...")
    ///     .build()?;
    /// server.up().await?;
    ///
    /// let mode = ServiceMode::tcp(8080).with_proxy_protocol(true);
    /// let mut listener = server.listen_service("svc:my-service", mode).await?;
    /// // loop { let stream = listener.accept().await?; ... }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Returns an error in TUN mode.
    pub async fn listen_service(
        &self,
        svc_name: &str,
        mode: ServiceMode,
    ) -> Result<ServiceListener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let netstack = match &inner.data_plane {
            DataPlane::Netstack(ns) => ns.clone(),
            DataPlane::Tun => return Err(TsnetError::NotAvailableInTunMode),
        };

        // Build a self node with the CapMap from magicsock (the authoritative
        // source for the self node's capabilities, updated from each
        // MapResponse).
        let cap_map = inner.magicsock.self_cap_map();
        let self_node = Node {
            Name: inner.our_fqdn.clone(),
            Addresses: inner
                .tailscale_ips
                .iter()
                .map(|ip| format!("{ip}/32"))
                .collect(),
            CapMap: cap_map,
            Tags: self.self_tags().await,
            ..Default::default()
        };

        let listener =
            service::create_service_listener(&netstack, &self_node, &inner.domain, svc_name, mode)
                .await?;

        Ok(listener)
    }

    /// Snapshot of this node's ACL tags from the self node in the peers list.
    /// Returns an empty vec if the self node is not found in the peers list.
    async fn self_tags(&self) -> Vec<String> {
        let Some(inner) = self.inner.as_ref() else {
            return vec![];
        };
        let peers = inner.peers.read().await;
        let our_fqdn = inner.our_fqdn.trim_end_matches('.');
        for peer in peers.iter() {
            if peer.Name.trim_end_matches('.') == our_fqdn {
                return peer.Tags.clone();
            }
        }
        vec![]
    }

    /// Snapshot of our own node from the netmap (peers list includes self
    /// on some control servers; otherwise we synthesize a minimal node from
    /// the retained DNS config + tailscale IPs for capability checks).
    async fn self_node(&self) -> Node {
        let inner = self.inner.as_ref().expect("self_node called before up()");
        let dns = inner.dns_config.read().await;
        let cert_domains: Vec<String> = dns
            .as_ref()
            .map(|c| c.CertDomains.clone())
            .unwrap_or_default();
        // If cert domains are present, the node has the `https` capability.
        let mut caps: Vec<String> = Vec::new();
        if !cert_domains.is_empty() {
            caps.push("https".to_string());
        }
        // The funnel node attribute is delivered in the self node's CapMap.
        // Since we don't retain the self node separately, we check the peers
        // list for our own node (by FQDN). If not found, the capability check
        // will return NotEnabled — the expected behavior on API-only tailnets.
        let peers = inner.peers.read().await;
        let our_fqdn = inner.our_fqdn.trim_end_matches('.');
        for peer in peers.iter() {
            if peer.Name.trim_end_matches('.') == our_fqdn {
                let mut n = peer.clone();
                if !caps.is_empty() && !n.Capabilities.contains(&caps[0]) {
                    n.Capabilities.extend(caps.clone());
                }
                return n;
            }
        }
        // Self not in peers list — synthesize a minimal node.
        Node {
            Name: inner.our_fqdn.clone(),
            Addresses: inner
                .tailscale_ips
                .iter()
                .map(|ip| format!("{ip}/32"))
                .collect(),
            Capabilities: caps,
            ..Default::default()
        }
    }

    /// Capture packets seen by the userspace netstack to a pcap file.
    ///
    /// Mirrors Go's `Server.CapturePcap`. The pcap file receives a raw stream
    /// of WireGuard-encapsulated packets (the same format as
    /// `tailscale debug capture`). A Lua dissector
    /// (`wgengine/capture/ts-dissector.lua` in the Go repo) is needed to
    /// decode the pcap in Wireshark.
    ///
    /// **Not yet implemented** in rustscale — returns
    /// [`TsnetError::NotSupported`]. The API is defined for parity so
    /// callers can write code that will work once the capture stream is
    /// wired in.
    #[allow(clippy::unused_async)] // async for API parity with Go's CapturePcap(ctx, file)
    pub async fn capture_pcap(&self, _pcap_file: &str) -> Result<(), TsnetError> {
        Err(TsnetError::NotSupported(
            "CapturePcap is not yet implemented in rustscale".into(),
        ))
    }

    /// Register a fallback TCP handler that is called when an incoming TCP
    /// flow to this node doesn't match any listener. Mirrors Go's
    /// `Server.RegisterFallbackTCPHandler`.
    ///
    /// If multiple handlers are registered, they are called in registration
    /// order. The first that returns `intercept=true` with a non-`None`
    /// handler closure takes over the connection.
    ///
    /// The returned [`FallbackTcpGuard`] removes the handler when dropped
    /// (equivalent to the `func()` deregister return value in Go).
    pub fn register_fallback_tcp_handler(
        &self,
        handler: Box<dyn FallbackTCPHandler + Send + Sync>,
    ) -> Result<FallbackTcpGuard, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let id = inner
            .fallback_next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        inner
            .fallback_tcp_handlers
            .lock()
            .expect("fallback mutex")
            .push((id, handler));
        Ok(FallbackTcpGuard {
            id,
            handlers: inner.fallback_tcp_handlers.clone(),
        })
    }
}

/// Guard returned by [`Server::register_fallback_tcp_handler`]. Dropping it
/// deregisters the handler (equivalent to the `func()` return value in Go's
/// `RegisterFallbackTCPHandler`).
pub struct FallbackTcpGuard {
    id: u64,
    handlers: Arc<std::sync::Mutex<Vec<(u64, Box<dyn FallbackTCPHandler + Send + Sync>)>>>,
}

impl Drop for FallbackTcpGuard {
    fn drop(&mut self) {
        if let Ok(mut v) = self.handlers.lock() {
            v.retain(|(id, _)| *id != self.id);
        }
    }
}
