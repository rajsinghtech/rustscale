//! Tailscale SSH server for rustscale — port of Go's `ssh/tailssh`.

mod auth;
mod c2n;
mod env;
mod hostkeys;
mod server;
pub mod session;

pub use auth::{eval_ssh_policy, ConnInfo, EvalResult};
pub use c2n::{get_ssh_usernames, handle_c2n_ssh_usernames, C2nSshUsernamesRequest, C2nSshUsernamesResponse};
pub use env::{accept_env_pair, filter_env};
pub use hostkeys::{host_key_from_node_key, host_key_public_string};
pub use server::{PolicyCallback, SshHandler, SshServer, SshServerConfig, WhoIsCallback};
pub use session::{PeerIdentity, Pty, Session, Window};

use std::sync::Arc;
use russh::server::{run_stream, Server as RusshServer};
use tokio::io::{AsyncRead, AsyncWrite};

/// Handle a single SSH connection on a stream.
pub async fn handle_ssh_conn<R>(
    config: Arc<russh::server::Config>,
    ssh_server: &mut SshServer,
    stream: R,
    peer_addr: Option<std::net::SocketAddr>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handler = ssh_server.new_client(peer_addr);
    let running = run_stream(config, stream, handler).await?;
    running.await?;
    Ok(())
}
