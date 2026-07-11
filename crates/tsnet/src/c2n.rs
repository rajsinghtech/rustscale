use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use rustscale_c2n::{C2nBackend, C2NServer, WhoIsResult};
use rustscale_controlclient::c2n::{C2nHandler, C2nRequest, C2nResponse};
use rustscale_tailcfg::{Node, UserID, UserProfile};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

pub struct EchoHandler;

#[async_trait]
impl C2nHandler for EchoHandler {
    async fn handle(&self, req: C2nRequest) -> C2nResponse {
        C2nResponse::ok(req.body)
    }
}

pub struct TsnetC2nBackend {
    peers: Arc<RwLock<Vec<Node>>>,
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
}

#[async_trait]
impl C2nBackend for TsnetC2nBackend {
    async fn whois(&self, ip: IpAddr) -> Option<WhoIsResult> {
        let peers = self.peers.try_read().ok()?;
        let user_profiles = self.user_profiles.try_read().ok()?;

        for peer in peers.iter() {
            let ips: Vec<IpAddr> = peer
                .Addresses
                .iter()
                .filter_map(|s| s.split('/').next().and_then(|p| p.parse::<IpAddr>().ok()))
                .collect();
            if ips.contains(&ip) {
                let up = user_profiles.get(&peer.User);
                return Some(WhoIsResult {
                    found: true,
                    node_name: peer.Name.clone(),
                    user_id: peer.User,
                    login_name: up.map(|p| p.LoginName.clone()).unwrap_or_default(),
                });
            }
        }
        None
    }
}

pub(crate) async fn spawn_c2n_server(
    peers: Arc<RwLock<Vec<Node>>>,
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    log_id: String,
) -> (JoinHandle<()>, SocketAddr) {
    let backend = Arc::new(TsnetC2nBackend {
        peers,
        user_profiles,
    });
    let server = C2NServer::new(backend, log_id);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("c2n: failed to bind loopback listener");
    let addr = listener.local_addr().expect("c2n: no local addr");

    let handle = tokio::spawn(async move {
        if let Err(e) = server.serve(listener).await {
            eprintln!("c2n server error: {e}");
        }
    });

    (handle, addr)
}
