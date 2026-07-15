//! Async client for the BIRD Internet Routing Daemon control socket.
//!
//! BIRD replies are parsed according to its four-digit control protocol.  A
//! reply line ending its response has a space after the code; a `-` denotes a
//! continuation.  Continuation lines may replace a repeated code with one
//! leading space.

#![forbid(unsafe_code)]

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Maximum amount of time to wait for each control-socket operation.
pub const DEFAULT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// A stream suitable for BIRD control-socket traffic.
pub trait BirdStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> BirdStream for T {}

/// Type-erased control stream returned by a [`Connector`].
pub type BoxedStream = Box<dyn BirdStream>;
/// Future returned by a [`Connector`].
pub type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<BoxedStream>> + Send + 'static>>;

/// Reusable connection factory.
///
/// Keeping the factory in the client permits an explicit [`BirdClient::reconnect`]
/// after EOF, timeout, or a daemon restart. Closures returning a
/// [`ConnectFuture`] implement this trait automatically.
pub trait Connector: Send + Sync {
    /// Open a new byte stream to BIRD.
    fn connect(&self) -> ConnectFuture;
}

impl<F> Connector for F
where
    F: Fn() -> ConnectFuture + Send + Sync,
{
    fn connect(&self) -> ConnectFuture {
        self()
    }
}

/// A parsed BIRD reply code.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResponseCode(u16);

impl ResponseCode {
    /// Numeric value of this four-digit code.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Whether this is a BIRD runtime or syntax error (8xxx or 9xxx).
    pub const fn is_error(self) -> bool {
        self.0 >= 8000
    }

    /// Whether this is an action-completed code (0xxx).
    pub const fn is_success(self) -> bool {
        self.0 < 1000
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}", self.0)
    }
}

/// One line in a BIRD response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseLine {
    /// Code on this line, or `None` for an abbreviated continuation line.
    pub code: Option<ResponseCode>,
    /// Text after the code and separator (or after the abbreviated leading space).
    pub text: String,
    /// Whether a coded line announced that more lines follow.
    pub continuation: bool,
}

/// A complete BIRD response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    raw: String,
    lines: Vec<ResponseLine>,
    final_code: ResponseCode,
}

impl Response {
    /// Response bytes represented as text, without the final line ending.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Parsed response lines.
    pub fn lines(&self) -> &[ResponseLine] {
        &self.lines
    }

    /// Code from the terminating response line.
    pub const fn final_code(&self) -> ResponseCode {
        self.final_code
    }

    /// First runtime or syntax error code in the response, if present.
    pub fn error_code(&self) -> Option<ResponseCode> {
        self.lines
            .iter()
            .filter_map(|line| line.code)
            .find(|code| code.is_error())
    }
}

/// Errors reported by the control client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Opening the control socket failed.
    #[error("failed to connect to BIRD: {0}")]
    Connect(#[source] io::Error),
    /// A control-socket operation exceeded its deadline.
    #[error("timed out while {operation} after {duration:?}")]
    Timeout {
        /// Operation that timed out.
        operation: &'static str,
        /// Configured timeout.
        duration: Duration,
    },
    /// An I/O operation failed.
    #[error("failed while {operation}: {source}")]
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// BIRD closed the stream before sending a terminating line.
    #[error("reading response from BIRD failed (EOF): {partial:?}")]
    UnexpectedEof {
        /// Response received before EOF.
        partial: String,
    },
    /// A response line did not follow the BIRD framing grammar.
    #[error("malformed BIRD response line {line_number}: {line:?}")]
    MalformedResponse {
        /// One-based line number.
        line_number: usize,
        /// Malformed line.
        line: String,
    },
    /// A response was larger than the client safety limit.
    #[error("BIRD response exceeded {limit} bytes")]
    ResponseTooLarge {
        /// Configured safety limit.
        limit: usize,
    },
    /// BIRD returned an 8xxx or 9xxx response code.
    #[error("BIRD rejected {command:?} with code {code}: {response}")]
    CommandRejected {
        /// Command sent to BIRD.
        command: String,
        /// First error response code.
        code: ResponseCode,
        /// Complete response.
        response: String,
    },
    /// BIRD completed a command but did not confirm the requested state.
    #[error("BIRD did not confirm {operation} for {subject:?}: {response}")]
    UnexpectedCommandResponse {
        /// Requested operation.
        operation: &'static str,
        /// Protocol or route involved.
        subject: String,
        /// Complete response.
        response: String,
    },
    /// A command contains a line ending or is empty.
    #[error("invalid BIRD command")]
    InvalidCommand,
    /// A protocol name cannot be safely represented as a BIRD token.
    #[error("invalid BIRD protocol name {0:?}")]
    InvalidProtocol(String),
    /// A route's prefix and gateway use different address families.
    #[error("route prefix {prefix} and gateway {gateway} use different address families")]
    AddressFamilyMismatch {
        /// Route prefix.
        prefix: IpPrefix,
        /// Route gateway.
        gateway: IpAddr,
    },
    /// The client has no live stream. Call `reconnect` before retrying.
    #[error("BIRD client is not connected")]
    NotConnected,
}

/// Error returned while parsing or constructing an IP prefix.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PrefixError {
    /// The CIDR slash was omitted.
    #[error("IP prefix must contain an address and prefix length")]
    MissingLength,
    /// The address was not valid IPv4 or IPv6.
    #[error("invalid IP address {0:?}")]
    InvalidAddress(String),
    /// The prefix length was not a decimal number.
    #[error("invalid prefix length {0:?}")]
    InvalidLength(String),
    /// The prefix length is too large for its address family.
    #[error("prefix length {length} is invalid for IPv{family}")]
    LengthOutOfRange {
        /// Supplied length.
        length: u16,
        /// Address family (4 or 6).
        family: u8,
    },
    /// A route prefix must be a canonical network, not an address with host bits.
    #[error("IP prefix {0} has host bits set")]
    HostBitsSet(String),
}

/// A validated, canonical IPv4 or IPv6 network prefix.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IpPrefix {
    addr: IpAddr,
    length: u8,
}

impl IpPrefix {
    /// Construct a network prefix.
    pub fn new(addr: IpAddr, length: u8) -> Result<Self, PrefixError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if length > max {
            return Err(PrefixError::LengthOutOfRange {
                length: u16::from(length),
                family: if addr.is_ipv4() { 4 } else { 6 },
            });
        }
        if !has_zero_host_bits(addr, length) {
            return Err(PrefixError::HostBitsSet(format!("{addr}/{length}")));
        }
        Ok(Self { addr, length })
    }

    /// Network address.
    pub const fn addr(self) -> IpAddr {
        self.addr
    }

    /// Number of network bits.
    pub const fn length(self) -> u8 {
        self.length
    }
}

impl FromStr for IpPrefix {
    type Err = PrefixError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (addr, length) = value.rsplit_once('/').ok_or(PrefixError::MissingLength)?;
        let addr = addr
            .parse::<IpAddr>()
            .map_err(|_| PrefixError::InvalidAddress(addr.to_owned()))?;
        let length = length
            .parse::<u16>()
            .map_err(|_| PrefixError::InvalidLength(length.to_owned()))?;
        let max = if addr.is_ipv4() { 32_u16 } else { 128_u16 };
        if length > max {
            return Err(PrefixError::LengthOutOfRange {
                length,
                family: if addr.is_ipv4() { 4 } else { 6 },
            });
        }
        Self::new(addr, length as u8)
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.length)
    }
}

fn has_zero_host_bits(addr: IpAddr, length: u8) -> bool {
    match addr {
        IpAddr::V4(addr) => {
            let value = u32::from(addr);
            let host_bits = 32 - u32::from(length);
            host_bits == 32 || value & ((1_u32 << host_bits) - 1) == 0
        }
        IpAddr::V6(addr) => {
            let value = u128::from(addr);
            let host_bits = 128 - u32::from(length);
            host_bits == 128 || value & ((1_u128 << host_bits) - 1) == 0
        }
    }
}

/// A unicast route installed through the BIRD CLI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    /// Destination network.
    pub prefix: IpPrefix,
    /// Next-hop address.
    pub gateway: IpAddr,
}

impl Route {
    /// Construct a route, rejecting mixed IPv4/IPv6 families.
    pub fn new(prefix: IpPrefix, gateway: IpAddr) -> Result<Self, Error> {
        if prefix.addr().is_ipv4() != gateway.is_ipv4() {
            return Err(Error::AddressFamilyMismatch { prefix, gateway });
        }
        Ok(Self { prefix, gateway })
    }
}

/// Connect to a BIRD Unix control socket with the default timeout.
///
/// This free function mirrors the upstream package constructor; the equivalent
/// associated constructor is [`BirdClient::new`].
pub async fn new(socket: impl AsRef<Path>) -> Result<BirdClient, Error> {
    BirdClient::new(socket).await
}

/// Async BIRD control-socket client.
pub struct BirdClient {
    connector: Arc<dyn Connector>,
    stream: Option<BufReader<BoxedStream>>,
    timeout: Duration,
}

/// Upstream-compatible spelling of [`BirdClient`].
#[allow(clippy::upper_case_acronyms)]
pub type BIRDClient = BirdClient;

impl BirdClient {
    /// Connect to a BIRD Unix control socket with the default timeout.
    pub async fn new(socket: impl AsRef<Path>) -> Result<Self, Error> {
        Self::with_timeout(socket, DEFAULT_RESPONSE_TIMEOUT).await
    }

    /// Connect to a BIRD Unix control socket with a custom timeout.
    #[cfg(unix)]
    pub async fn with_timeout(
        socket: impl AsRef<Path>,
        operation_timeout: Duration,
    ) -> Result<Self, Error> {
        let socket = socket.as_ref().to_owned();
        let connector: Arc<dyn Connector> = Arc::new(move || unix_connect(socket.clone()));
        Self::with_connector(connector, operation_timeout).await
    }

    /// Return an unsupported-platform error for Unix sockets on non-Unix hosts.
    #[cfg(not(unix))]
    pub async fn with_timeout(
        _socket: impl AsRef<Path>,
        _operation_timeout: Duration,
    ) -> Result<Self, Error> {
        Err(Error::Connect(io::Error::new(
            io::ErrorKind::Unsupported,
            "BIRD Unix sockets are unavailable on this platform",
        )))
    }

    /// Connect to a TCP endpoint. This is useful for isolated proxies and tests;
    /// production BIRD deployments normally use [`Self::new`].
    pub async fn connect_tcp(
        address: SocketAddr,
        operation_timeout: Duration,
    ) -> Result<Self, Error> {
        let connector: Arc<dyn Connector> = Arc::new(move || tcp_connect(address));
        Self::with_connector(connector, operation_timeout).await
    }

    /// Connect with an injectable reusable stream factory.
    pub async fn with_connector(
        connector: Arc<dyn Connector>,
        operation_timeout: Duration,
    ) -> Result<Self, Error> {
        let mut client = Self {
            connector,
            stream: None,
            timeout: operation_timeout,
        };
        client.open().await?;
        Ok(client)
    }

    /// Reopen the configured endpoint and consume the new BIRD greeting.
    ///
    /// The old stream is always dropped first. A failed reconnect leaves the
    /// client disconnected so a later call may try again.
    pub async fn reconnect(&mut self) -> Result<(), Error> {
        self.stream = None;
        self.open().await
    }

    /// Close the underlying stream. Calling this more than once is harmless.
    pub async fn close(&mut self) -> Result<(), Error> {
        let Some(mut stream) = self.stream.take() else {
            return Ok(());
        };
        match timeout(self.timeout, stream.get_mut().shutdown()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(Error::Io {
                operation: "closing the BIRD connection",
                source,
            }),
            Err(_) => Err(Error::Timeout {
                operation: "closing the BIRD connection",
                duration: self.timeout,
            }),
        }
    }

    /// Enable a BIRD protocol. "Already enabled" is treated as success.
    pub async fn enable_protocol(&mut self, protocol: &str) -> Result<(), Error> {
        self.change_protocol("enable", "enabled", protocol).await
    }

    /// Disable a BIRD protocol. "Already disabled" is treated as success.
    pub async fn disable_protocol(&mut self, protocol: &str) -> Result<(), Error> {
        self.change_protocol("disable", "disabled", protocol).await
    }

    /// Add a route using BIRD's `add route` CLI command.
    pub async fn add_route(&mut self, route: Route) -> Result<(), Error> {
        let command = format!("add route {} via {}", route.prefix, route.gateway);
        self.execute_action(&command, "add route", route.prefix.to_string())
            .await
    }

    /// Remove a route using BIRD's `delete route` CLI command.
    pub async fn remove_route(&mut self, prefix: IpPrefix) -> Result<(), Error> {
        let command = format!("delete route {prefix}");
        self.execute_action(&command, "remove route", prefix.to_string())
            .await
    }

    /// Replace a route using BIRD's `replace route` CLI command.
    pub async fn replace_route(&mut self, route: Route) -> Result<(), Error> {
        let command = format!("replace route {} via {}", route.prefix, route.gateway);
        self.execute_action(&command, "replace route", route.prefix.to_string())
            .await
    }

    /// Execute one control command and return its parsed response.
    ///
    /// Commands are sent as one line terminated by `\n`. Empty commands and
    /// embedded line endings are rejected. Runtime and syntax replies become
    /// [`Error::CommandRejected`].
    pub async fn execute(&mut self, command: &str) -> Result<Response, Error> {
        if command.is_empty() || command.contains(['\r', '\n']) {
            return Err(Error::InvalidCommand);
        }
        let response = self.execute_raw(command).await?;
        if let Some(code) = response.error_code() {
            return Err(Error::CommandRejected {
                command: command.to_owned(),
                code,
                response: response.raw,
            });
        }
        Ok(response)
    }

    async fn open(&mut self) -> Result<(), Error> {
        let stream = match timeout(self.timeout, self.connector.connect()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(source)) => return Err(Error::Connect(source)),
            Err(_) => {
                return Err(Error::Timeout {
                    operation: "connecting to BIRD",
                    duration: self.timeout,
                });
            }
        };
        self.stream = Some(BufReader::new(stream));
        if let Err(error) = self.read_response().await {
            self.stream = None;
            return Err(error);
        }
        Ok(())
    }

    async fn change_protocol(
        &mut self,
        command: &'static str,
        state: &'static str,
        protocol: &str,
    ) -> Result<(), Error> {
        validate_protocol(protocol)?;
        let response = self.execute(&format!("{command} {protocol}")).await?;
        let changed = format!("{protocol}: {state}");
        let unchanged = format!("{protocol}: already {state}");
        if response.raw().contains(&changed) || response.raw().contains(&unchanged) {
            return Ok(());
        }
        Err(Error::UnexpectedCommandResponse {
            operation: command,
            subject: protocol.to_owned(),
            response: response.raw,
        })
    }

    async fn execute_action(
        &mut self,
        command: &str,
        operation: &'static str,
        subject: String,
    ) -> Result<(), Error> {
        let response = self.execute(command).await?;
        if response.final_code().is_success() {
            Ok(())
        } else {
            Err(Error::UnexpectedCommandResponse {
                operation,
                subject,
                response: response.raw,
            })
        }
    }

    async fn execute_raw(&mut self, command: &str) -> Result<Response, Error> {
        let bytes = format!("{command}\n");
        let Some(stream) = self.stream.as_mut() else {
            return Err(Error::NotConnected);
        };
        let write_result =
            timeout(self.timeout, stream.get_mut().write_all(bytes.as_bytes())).await;
        match write_result {
            Ok(Ok(())) => {}
            Ok(Err(source)) => {
                self.stream = None;
                return Err(Error::Io {
                    operation: "writing a BIRD command",
                    source,
                });
            }
            Err(_) => {
                self.stream = None;
                return Err(Error::Timeout {
                    operation: "writing a BIRD command",
                    duration: self.timeout,
                });
            }
        }
        let response = self.read_response().await;
        // No read failure is safely recoverable on the same stream: bytes from
        // a late or malformed reply could otherwise be mistaken for the next
        // command's response.
        if response.is_err() {
            self.stream = None;
        }
        response
    }

    async fn read_response(&mut self) -> Result<Response, Error> {
        let operation_timeout = self.timeout;
        match timeout(operation_timeout, self.read_response_inner()).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout {
                operation: "reading a BIRD response",
                duration: operation_timeout,
            }),
        }
    }

    async fn read_response_inner(&mut self) -> Result<Response, Error> {
        let Some(stream) = self.stream.as_mut() else {
            return Err(Error::NotConnected);
        };
        let mut raw = String::new();
        let mut lines = Vec::new();
        let mut wire_line = Vec::new();
        let mut continuation_expected = false;

        loop {
            wire_line.clear();
            let count = stream
                .read_until(b'\n', &mut wire_line)
                .await
                .map_err(|source| Error::Io {
                    operation: "reading a BIRD response",
                    source,
                })?;
            if count == 0 {
                return Err(Error::UnexpectedEof { partial: raw });
            }
            if wire_line.ends_with(b"\n") {
                wire_line.pop();
                if wire_line.ends_with(b"\r") {
                    wire_line.pop();
                }
            }
            if raw.len() + wire_line.len() > MAX_RESPONSE_SIZE {
                return Err(Error::ResponseTooLarge {
                    limit: MAX_RESPONSE_SIZE,
                });
            }
            let line = std::str::from_utf8(&wire_line).map_err(|_| Error::MalformedResponse {
                line_number: lines.len() + 1,
                line: String::from_utf8_lossy(&wire_line).into_owned(),
            })?;
            if !raw.is_empty() {
                raw.push('\n');
            }
            raw.push_str(line);

            let parsed = parse_response_line(line, lines.len() + 1, continuation_expected)?;
            let done = parsed.code.is_some() && !parsed.continuation;
            continuation_expected =
                parsed.continuation || (parsed.code.is_none() && continuation_expected);
            let final_code = parsed.code;
            lines.push(parsed);
            if done {
                return Ok(Response {
                    raw,
                    lines,
                    final_code: final_code.expect("coded terminal response line"),
                });
            }
        }
    }
}

#[cfg(unix)]
fn unix_connect(socket: PathBuf) -> ConnectFuture {
    Box::pin(async move {
        let stream = tokio::net::UnixStream::connect(socket).await?;
        Ok(Box::new(stream) as BoxedStream)
    })
}

fn tcp_connect(address: SocketAddr) -> ConnectFuture {
    Box::pin(async move {
        let stream = TcpStream::connect(address).await?;
        Ok(Box::new(stream) as BoxedStream)
    })
}

fn validate_protocol(protocol: &str) -> Result<(), Error> {
    if protocol.is_empty()
        || !protocol
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(Error::InvalidProtocol(protocol.to_owned()));
    }
    Ok(())
}

fn parse_response_line(
    line: &str,
    line_number: usize,
    continuation_expected: bool,
) -> Result<ResponseLine, Error> {
    let bytes = line.as_bytes();
    if bytes.len() >= 5
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && matches!(bytes[4], b' ' | b'-')
    {
        let code = bytes[..4]
            .iter()
            .fold(0_u16, |value, digit| value * 10 + u16::from(digit - b'0'));
        return Ok(ResponseLine {
            code: Some(ResponseCode(code)),
            text: line[5..].to_owned(),
            continuation: bytes[4] == b'-',
        });
    }
    if continuation_expected && bytes.first() == Some(&b' ') {
        return Ok(ResponseLine {
            code: None,
            text: line[1..].to_owned(),
            continuation: true,
        });
    }
    Err(Error::MalformedResponse {
        line_number,
        line: line.to_owned(),
    })
}

#[cfg(test)]
mod tests;
