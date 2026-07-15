//! Bounded Tailnet Lock RPCs over authenticated ts2021 Noise sessions.

use std::time::Duration;

use rustscale_key::NodePublic;
use rustscale_tailcfg::{
    TKABootstrapRequest, TKABootstrapResponse, TKADisableRequest, TKADisableResponse,
    TKAInitBeginRequest, TKAInitBeginResponse, TKAInitFinishRequest, TKAInitFinishResponse,
    TKASubmitSignatureRequest, TKASubmitSignatureResponse, TKASyncOfferRequest,
    TKASyncOfferResponse, TKASyncSendRequest, TKASyncSendResponse,
};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{ControlClient, NoiseHttpClient, NoiseRequestError, NoiseResponseBody};

/// AUM exchanges are bounded below the map-response limit and well below an
/// unbounded allocation. Canonical CBOR has its own per-AUM 1 MiB bound.
pub const MAX_TKA_REQUEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_TKA_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
pub const TKA_RPC_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum TkaRpcError {
    #[error("Tailnet Lock request encoding failed")]
    Encode(#[source] serde_json::Error),
    #[error("Tailnet Lock response decoding failed")]
    Decode(#[source] serde_json::Error),
    #[error("Tailnet Lock transport failed")]
    Transport(#[source] NoiseRequestError),
    #[error("Tailnet Lock control request returned HTTP {0}")]
    HttpStatus(u16),
    #[error("Tailnet Lock request exceeded {MAX_TKA_REQUEST_BYTES} bytes")]
    RequestTooLarge,
    #[error("Tailnet Lock response exceeded {MAX_TKA_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    #[error("Tailnet Lock control request timed out")]
    Timeout,
}

/// Factory for bounded Tailnet Lock sessions.
pub struct TkaClient<'a> {
    control: &'a ControlClient,
}

/// One reusable HTTP/2-over-Noise connection. Multi-step init and sync flows
/// issue every RPC on this same authenticated session. Dropping the session
/// closes the transport and cancels outstanding streams.
pub struct TkaSession {
    client: NoiseHttpClient,
}

struct PreparedRequest {
    body: Vec<u8>,
    node_key: NodePublic,
}

impl<'a> TkaClient<'a> {
    pub fn new(control: &'a ControlClient) -> Self {
        Self { control }
    }

    pub async fn connect(&self) -> Result<TkaSession, TkaRpcError> {
        let client = tokio::time::timeout(TKA_RPC_DEADLINE, self.control.connect())
            .await
            .map_err(|_| TkaRpcError::Timeout)?
            .map_err(TkaRpcError::Transport)?;
        Ok(TkaSession { client })
    }

    pub async fn init_begin(
        &self,
        request: &TKAInitBeginRequest,
    ) -> Result<TKAInitBeginResponse, TkaRpcError> {
        self.single("/machine/tka/init/begin", request).await
    }

    pub async fn init_finish(
        &self,
        request: &TKAInitFinishRequest,
    ) -> Result<TKAInitFinishResponse, TkaRpcError> {
        self.single("/machine/tka/init/finish", request).await
    }

    pub async fn bootstrap(
        &self,
        request: &TKABootstrapRequest,
    ) -> Result<TKABootstrapResponse, TkaRpcError> {
        self.single("/machine/tka/bootstrap", request).await
    }

    pub async fn sync_offer(
        &self,
        request: &TKASyncOfferRequest,
    ) -> Result<TKASyncOfferResponse, TkaRpcError> {
        self.single("/machine/tka/sync/offer", request).await
    }

    pub async fn sync_send(
        &self,
        request: &TKASyncSendRequest,
    ) -> Result<TKASyncSendResponse, TkaRpcError> {
        self.single("/machine/tka/sync/send", request).await
    }

    pub async fn disable(
        &self,
        request: &TKADisableRequest,
    ) -> Result<TKADisableResponse, TkaRpcError> {
        self.single("/machine/tka/disable", request).await
    }

    pub async fn submit_signature(
        &self,
        request: &TKASubmitSignatureRequest,
    ) -> Result<TKASubmitSignatureResponse, TkaRpcError> {
        self.single("/machine/tka/sign", request).await
    }

    async fn single<Req, Resp>(
        &self,
        path: &'static str,
        request: &Req,
    ) -> Result<Resp, TkaRpcError>
    where
        Req: Serialize,
        Resp: DeserializeOwned,
    {
        // Prepare before dialing so an oversized or malformed local request
        // cannot consume a control connection.
        let prepared = prepare_request(request)?;
        self.connect().await?.call(path, prepared).await
    }
}

impl TkaSession {
    pub async fn init_begin(
        &self,
        request: &TKAInitBeginRequest,
    ) -> Result<TKAInitBeginResponse, TkaRpcError> {
        self.call("/machine/tka/init/begin", prepare_request(request)?)
            .await
    }

    pub async fn init_finish(
        &self,
        request: &TKAInitFinishRequest,
    ) -> Result<TKAInitFinishResponse, TkaRpcError> {
        self.call("/machine/tka/init/finish", prepare_request(request)?)
            .await
    }

    pub async fn bootstrap(
        &self,
        request: &TKABootstrapRequest,
    ) -> Result<TKABootstrapResponse, TkaRpcError> {
        self.call("/machine/tka/bootstrap", prepare_request(request)?)
            .await
    }

    pub async fn sync_offer(
        &self,
        request: &TKASyncOfferRequest,
    ) -> Result<TKASyncOfferResponse, TkaRpcError> {
        self.call("/machine/tka/sync/offer", prepare_request(request)?)
            .await
    }

    pub async fn sync_send(
        &self,
        request: &TKASyncSendRequest,
    ) -> Result<TKASyncSendResponse, TkaRpcError> {
        self.call("/machine/tka/sync/send", prepare_request(request)?)
            .await
    }

    pub async fn disable(
        &self,
        request: &TKADisableRequest,
    ) -> Result<TKADisableResponse, TkaRpcError> {
        self.call("/machine/tka/disable", prepare_request(request)?)
            .await
    }

    pub async fn submit_signature(
        &self,
        request: &TKASubmitSignatureRequest,
    ) -> Result<TKASubmitSignatureResponse, TkaRpcError> {
        self.call("/machine/tka/sign", prepare_request(request)?)
            .await
    }

    async fn call<Resp>(
        &self,
        path: &'static str,
        prepared: PreparedRequest,
    ) -> Result<Resp, TkaRpcError>
    where
        Resp: DeserializeOwned,
    {
        tokio::time::timeout(TKA_RPC_DEADLINE, async {
            // Upstream's Tailnet Lock Noise RPCs intentionally use GET with
            // a JSON body. Preserve that unusual method for wire parity.
            let request = http::Request::builder()
                .method("GET")
                .uri(path)
                .header("content-type", "application/json")
                .header("Ts-Lb", prepared.node_key.to_string())
                .body(prepared.body)
                .map_err(|error| {
                    TkaRpcError::Transport(NoiseRequestError::Io(std::io::Error::other(error)))
                })?;
            let response = self
                .client
                .request(request)
                .await
                .map_err(TkaRpcError::Transport)?;
            let status = response.status();
            let mut body = response.into_body();
            let bytes = read_bounded(&mut body).await?;
            if status != 200 {
                // Deliberately do not reflect a control response body: it may
                // contain request context or disablement/signing material.
                return Err(TkaRpcError::HttpStatus(status));
            }
            let bytes = if bytes.is_empty() {
                b"{}".as_slice()
            } else {
                &bytes
            };
            serde_json::from_slice(bytes).map_err(TkaRpcError::Decode)
        })
        .await
        .map_err(|_| TkaRpcError::Timeout)?
    }
}

fn prepare_request<T: Serialize>(request: &T) -> Result<PreparedRequest, TkaRpcError> {
    let body = serde_json::to_vec(request).map_err(TkaRpcError::Encode)?;
    if body.len() > MAX_TKA_REQUEST_BYTES {
        return Err(TkaRpcError::RequestTooLarge);
    }
    Ok(PreparedRequest {
        body,
        node_key: request_node_key(request)?,
    })
}

/// All TKA request types place NodeKey under the same exact JSON field. Read it
/// from the typed request without accepting a second, potentially inconsistent
/// identity argument.
fn request_node_key<T: Serialize>(request: &T) -> Result<NodePublic, TkaRpcError> {
    #[derive(serde::Deserialize)]
    struct Identity {
        #[serde(rename = "NodeKey")]
        node_key: NodePublic,
    }
    let value = serde_json::to_value(request).map_err(TkaRpcError::Encode)?;
    serde_json::from_value::<Identity>(value)
        .map(|identity| identity.node_key)
        .map_err(TkaRpcError::Decode)
}

async fn read_bounded(body: &mut NoiseResponseBody) -> Result<Vec<u8>, TkaRpcError> {
    let mut output = Vec::new();
    while let Some(chunk) = body
        .data()
        .await
        .map_err(|error| TkaRpcError::Transport(NoiseRequestError::H2(error)))?
    {
        if output.len().saturating_add(chunk.len()) > MAX_TKA_RESPONSE_BYTES {
            body.cancel();
            return Err(TkaRpcError::ResponseTooLarge);
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::{MachinePrivate, NodePrivate};

    #[tokio::test]
    async fn oversized_request_is_rejected_before_dial() {
        let control = ControlClient::new(
            "http://127.0.0.1:1",
            MachinePrivate::generate(),
            MachinePrivate::generate().public(),
            141,
        );
        let request = TKASyncSendRequest {
            Version: 141,
            NodeKey: NodePrivate::generate().public(),
            Head: "head".into(),
            MissingAUMs: vec![vec![0; MAX_TKA_REQUEST_BYTES]],
            Interactive: false,
        };
        assert!(matches!(
            TkaClient::new(&control).sync_send(&request).await,
            Err(TkaRpcError::RequestTooLarge)
        ));
    }
}
