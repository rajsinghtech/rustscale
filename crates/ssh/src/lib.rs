//! Tailscale SSH server for rustscale — a port of Go's
//! `tailscale.com/ssh/tailssh` package.
//!
//! Provides an SSH server that integrates with rustscale's tsnet, allowing
//! tsnet embedders to accept SSH connections authenticated by the Tailscale
//! control plane. The server:
//!
//! - Listens on a tailnet address (via a netstack listener or raw TCP stream)
//! - Authenticates using the Tailscale node identity (no passwords/keys)
//! - Authorizes based on SSH grants in the tailnet policy file
//! - Supports SSH sessions (shell, exec, subsystem)
//! - Generates host keys deterministically from the node key
//!
//! # Quick start
//!
//! ```no_run
//! # use rustscale_ssh::*;
//! # use rustscale_tailcfg::*;
//! # use std::sync::Arc;
//! # async fn demo() {
//! let (session_tx, mut session_rx) = tokio::sync::mpsc::channel(16);
//!
//! let config = SshServerConfig {
//!     host_keys: vec![host_key_from_node_key(&rustscale_key::NodePrivate::generate())],
//!     session_tx,
//!     whois: Arc::new(|_ip| None),
//!     policy: Arc::new(|| None),
//! };
//!
//! let server = SshServer::new(config);
//! let russh_config = server.russh_config();
//!
//! // In tsnet: accept a NetstackStream and pass it to run_stream:
//! // russh::server::run_stream(russh_config, stream, handler).await
//! # }
//! ```

mod auth;
mod c2n;
mod env;
mod hostkeys;
mod server;
mod session;

pub use auth::{eval_ssh_policy, ConnInfo, EvalResult};
pub use c2n::{
    get_ssh_usernames, handle_c2n_ssh_usernames, C2nSshUsernamesRequest, C2nSshUsernamesResponse,
};
pub use env::{accept_env_pair, filter_env};
pub use hostkeys::{host_key_from_node_key, host_key_public_string};
pub use server::{PolicyCallback, SshHandler, SshServer, SshServerConfig, WhoIsCallback};
pub use session::{PeerIdentity, Pty, Session, Window};

use russh::server::run_stream;
use tokio::io::{AsyncRead, AsyncWrite};

/// Handle a single SSH connection on a stream.
///
/// This is the entry point for processing an SSH connection from a raw
/// stream (e.g. a `NetstackStream` from tsnet). It runs the SSH server
/// protocol, performs Tailscale authentication, and sends accepted
/// sessions through the `SshServerConfig`'s `session_tx` channel.
pub async fn handle_ssh_conn<R>(
    config: Arc<russh::server::Config>,
    ssh_server: &mut SshServer,
    stream: R,
) -> Result<(), russh::Error>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let handler = ssh_server.new_client(None);
    let running = run_stream(config, stream, handler).await?;
    running.await.map_err(|e| russh::Error::IO(e.into()))
}
