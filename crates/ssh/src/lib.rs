//! Tailscale SSH server for rustscale — port of Go's `ssh/tailssh`.

mod auth;
mod c2n;
mod env;
mod hostkeys;
pub mod incubator;
pub mod recording;
pub mod recording_upload;
mod server;
pub mod session;
pub mod session_handler;
#[cfg(test)]
mod tests;

pub use auth::{eval_ssh_policy, ConnInfo, EvalResult};
pub use c2n::{
    get_ssh_usernames, handle_c2n_ssh_usernames, C2nSshUsernamesRequest, C2nSshUsernamesResponse,
};
pub use env::{accept_env_pair, filter_env};
pub use hostkeys::{host_key_from_node_key, host_key_public_string};
pub use incubator::{Incubator, IncubatorArgs, IncubatorError, SpawnedProcess};
pub use recording::{
    default_recording_path, CastHeader, RecordDir, RecordResult, RecordingConfig, SessionRecorder,
};
pub use recording_upload::{connect_to_recorder, BoxedIo, DialFn, RecordingConnection};
pub use server::{PolicyCallback, SshHandler, SshServer, SshServerConfig, WhoIsCallback};
pub use session::{PeerIdentity, Pty, Session, Window};
pub use session_handler::{run_session, SessionHandlerError};

use russh::server::{run_stream, Server as RusshServer};
use std::sync::Arc;
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
