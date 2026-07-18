# Conceptual `tsnet` mapping

Generated from `tailscale.com@v1.100.0` and the
`rustscale-tsnet` all-features rustdoc artifact. This table maps concepts;
`semantic` does not assert byte-for-byte signatures or runtime parity.

| Upstream identifier | Rust identifier(s) | Classification | Note |
| --- | --- | --- | --- |
| `field:Server.AdvertiseTags` | `method:ServerBuilder.advertise_tags` | semantic | idiomatic Rust spelling/type adaptation |
| `field:Server.Audience` | `method:ServerBuilder.audience` | semantic | idiomatic Rust spelling/type adaptation |
| `field:Server.AuthKey` | `method:ServerBuilder.auth_key` | semantic | idiomatic Rust spelling/type adaptation |
| `field:Server.ClientID` | `method:ServerBuilder.client_id` | semantic | idiomatic Rust spelling/type adaptation |
| `field:Server.ClientSecret` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `field:Server.ControlURL` | `method:ServerBuilder.control_url` | semantic | idiomatic Rust spelling/type adaptation |
| `field:Server.Dir` | `method:ServerBuilder.state_dir` | semantic | Rust configures the identity/state directory through the builder |
| `field:Server.Ephemeral` | `method:ServerBuilder.ephemeral` | semantic | idiomatic Rust spelling/type adaptation |
| `field:Server.Hostname` | `method:ServerBuilder.hostname` | semantic | idiomatic Rust spelling/type adaptation |
| `field:Server.IDToken` | `method:ServerBuilder.id_token` | semantic | idiomatic Rust spelling/type adaptation |
| `field:Server.Logf` | `method:ServerBuilder.logger` | semantic | Rust uses one typed builder callback for server logging |
| `field:Server.Port` | `method:ServerBuilder.port` | semantic | idiomatic Rust spelling/type adaptation |
| `field:Server.RunWebClient` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `field:Server.Store` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `field:Server.Tun` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `field:Server.UserLogf` | `method:ServerBuilder.logger` | semantic | Rust routes user-facing and server log text through the builder logger |
| `field:ServiceListener.FQDN` | `method:ServiceListener.fqdn` | semantic | Rust exposes the service FQDN through an accessor |
| `field:ServiceListener.Listener` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `field:ServiceModeHTTP.AcceptAppCaps` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `field:ServiceModeHTTP.HTTPS` | `method:ServiceMode.https` | semantic | Rust represents HTTPS as a ServiceMode constructor |
| `field:ServiceModeHTTP.PROXYProtocol` | `method:ServiceMode.with_proxy_protocol` | semantic | Rust enables the supported PROXY protocol through a mode builder |
| `field:ServiceModeHTTP.Port` | `method:ServiceMode.port` | semantic | Rust exposes a common service-mode port accessor |
| `field:ServiceModeTCP.PROXYProtocolVersion` | `method:ServiceMode.with_proxy_protocol` | semantic | Rust supports the implemented PROXY protocol through a boolean mode builder |
| `field:ServiceModeTCP.Port` | `method:ServiceMode.port` | semantic | Rust exposes a common service-mode port accessor |
| `field:ServiceModeTCP.TerminateTLS` | `method:ServiceMode.https` | semantic | Rust represents TLS termination as HTTPS service mode |
| `function:FunnelOnly` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `function:FunnelTLSConfig` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `method:Server.CapturePcap` | `method:Server.capture_pcap` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.CertDomains` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `method:Server.Close` | `method:Server.close` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.Dial` | `method:Server.dial` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.GetRootPath` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `method:Server.HTTPClient` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `method:Server.Listen` | `method:Server.listen` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.ListenFunnel` | `method:Server.listen_funnel` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.ListenPacket` | `method:Server.listen_packet` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.ListenSSH` | `method:Server.listen_ssh` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.ListenService` | `method:Server.listen_service` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.ListenTLS` | `method:Server.listen_tls` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.LocalClient` | `method:Server.local_client` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.LogtailWriter` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `method:Server.Loopback` | `method:Server.loopback` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.RegisterFallbackTCPHandler` | `method:Server.register_fallback_tcp_handler` | semantic | idiomatic Rust spelling/type adaptation |
| `method:Server.Start` | `method:Server.ensure_up` | semantic | ensure_up is the idempotent async start operation |
| `method:Server.Sys` | `method:Server.system` | semantic | Rust spells the typed dependency container accessor system |
| `method:Server.TailscaleIPs` | `method:Server.status` | semantic | Rust returns assigned addresses in the ServerStatus snapshot |
| `method:Server.Up` | `method:Server.up` | semantic | idiomatic Rust spelling/type adaptation |
| `method:ServiceListener.Addr` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `method:ServiceListener.Close` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `type:FallbackTCPHandler` | `trait:FallbackTCPHandler` | semantic | idiomatic Rust spelling/type adaptation |
| `type:FunnelOption` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `type:Server` | `struct:Server` | semantic | idiomatic Rust spelling/type adaptation |
| `type:ServiceListener` | `struct:ServiceListener` | semantic | idiomatic Rust spelling/type adaptation |
| `type:ServiceMode` | `enum:ServiceMode` | semantic | idiomatic Rust spelling/type adaptation |
| `type:ServiceModeHTTP` | `enum:ServiceMode` | semantic | Rust uses one enum for TCP, HTTP, and HTTPS service modes |
| `type:ServiceModeTCP` | `enum:ServiceMode` | semantic | Rust uses one enum for TCP, HTTP, and HTTPS service modes |
| `var:ErrUntaggedServiceHost` | — | unsupported | no reviewed rustscale tsnet equivalent |
| `var:TestHooks` | — | unsupported | no reviewed rustscale tsnet equivalent |
