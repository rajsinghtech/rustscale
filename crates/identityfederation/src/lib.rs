//! Workload identity federation auth-key resolution.
//!
//! This package implements the client-side Tailscale flow: exchange a provider
//! ID token for an access token, then use that token to create a tagged,
//! one-use auth key. Provider credential discovery is deliberately outside this
//! crate; callers may supply a [`ProviderTokenSource`] for their environment.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

/// Default API/control base used when no URL is supplied.
pub const DEFAULT_CONTROL_URL: &str = "https://controlplane.tailscale.com";
/// Default API base used for OAuth client-secret auth-key creation.
pub const DEFAULT_API_URL: &str = "https://api.tailscale.com";
/// Tailscale's token exchange timeout.
pub const DEFAULT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for an injected provider token source.
pub const DEFAULT_PROVIDER_TIMEOUT: Duration = Duration::from_secs(5);
/// OAuth's maximum token response size.
pub const MAX_TOKEN_RESPONSE_SIZE: usize = 1 << 20;
/// Maximum response size used by the Tailscale API client.
pub const MAX_API_RESPONSE_SIZE: usize = 10 << 20;

/// URL trust policy for control-plane requests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UrlPolicy {
    /// Require HTTPS. This is the production default.
    #[default]
    HttpsOnly,
    /// Also allow plain HTTP when the destination is a loopback address.
    /// Intended for hermetic tests and local development control servers.
    HttpsOrLoopbackHttp,
}

/// A provider identity-token source.
///
/// Implementations can integrate a workload platform without exposing cloud
/// credentials to this package. Returned errors are intentionally not included
/// in user-facing federation errors, because provider errors can contain bearer
/// tokens.
#[async_trait]
pub trait ProviderTokenSource: Send + Sync {
    async fn token(&self, audience: &str) -> Result<String, ProviderTokenError>;
}

/// Error from an injected provider token source.
///
/// The message must not contain credentials or tokens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderTokenError(String);

impl ProviderTokenError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ProviderTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProviderTokenError {}

#[derive(Debug, Default)]
struct NoProviderTokenSource;

#[async_trait]
impl ProviderTokenSource for NoProviderTokenSource {
    async fn token(&self, _audience: &str) -> Result<String, ProviderTokenError> {
        Err(ProviderTokenError::new(
            "no provider token source configured",
        ))
    }
}

/// A minimal HTTP request used by the injectable transport.
///
/// This type intentionally does not implement `Debug`: headers and bodies can
/// contain identity and access tokens.
pub struct HttpRequest {
    pub method: &'static str,
    pub url: Url,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A minimal HTTP response used by the injectable transport.
///
/// This type intentionally does not implement `Debug`: response bodies can
/// contain access tokens and auth keys.
pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// Transport failure. Messages must not contain request credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpError(String);

impl HttpError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HttpError {}

/// Injectable HTTP transport.
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpError>;
}

/// Reqwest-backed production transport. Redirects are disabled so credentials
/// cannot be forwarded to a different origin.
pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

impl ReqwestHttpClient {
    pub fn new() -> Result<Self, HttpError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| HttpError::new("failed to initialize HTTP client"))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| HttpError::new("invalid HTTP method"))?;
        let mut builder = self.client.request(method, request.url);
        for (name, value) in request.headers {
            builder = builder.header(&name, &value);
        }
        let mut response = builder
            .body(request.body)
            .send()
            .await
            .map_err(|_| HttpError::new("HTTP request failed"))?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| HttpError::new("failed to read HTTP response"))?
        {
            body.extend_from_slice(&chunk);
            // The operation-specific limit is enforced by FederationClient.
            // This absolute ceiling prevents an injected or unexpectedly large
            // network response from growing without bound first.
            if body.len() > MAX_API_RESPONSE_SIZE + 1 {
                break;
            }
        }
        Ok(HttpResponse {
            status,
            content_type,
            body,
        })
    }
}

/// Parsed optional attributes carried in the federated client ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdAttributes {
    pub client_id: String,
    pub ephemeral: bool,
    pub preauthorized: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OAuthSecretAttributes {
    client_secret: String,
    ephemeral: bool,
    preauthorized: bool,
    base_url: String,
}

/// Workload identity federation failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    MissingTokenOrAudience,
    MissingTags,
    MissingOAuthTags,
    InvalidOptionalAttributes(String),
    ProviderTokenRequired,
    UntrustedUrl,
    RequestTimeout(&'static str),
    RequestFailed(&'static str),
    ResponseTooLarge(&'static str),
    HttpStatus {
        operation: &'static str,
        status: u16,
    },
    MalformedResponse(&'static str),
    OAuthError,
    EmptyAccessToken,
    EmptyAuthKey,
    TokenExchange(String),
    CreateAuthKey(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTokenOrAudience => {
                f.write_str("federated identity requires either an ID token or an audience")
            }
            Self::MissingTags => {
                f.write_str("federated identity authkeys require --advertise-tags")
            }
            Self::MissingOAuthTags => f.write_str("oauth authkeys require --advertise-tags"),
            Self::InvalidOptionalAttributes(error) => {
                write!(f, "failed to parse optional config attributes: {error}")
            }
            Self::ProviderTokenRequired => {
                f.write_str("federated identity authkeys require --id-token")
            }
            Self::UntrustedUrl => f.write_str("untrusted control server URL"),
            Self::RequestTimeout(operation) => write!(f, "{operation} timed out"),
            Self::RequestFailed(operation) => write!(f, "{operation} request failed"),
            Self::ResponseTooLarge(operation) => write!(f, "{operation} response too large"),
            Self::HttpStatus { operation, status } => {
                write!(f, "{operation} failed with status {status}")
            }
            Self::MalformedResponse(operation) => {
                write!(f, "malformed {operation} response")
            }
            Self::OAuthError => f.write_str("token exchange returned an OAuth error"),
            Self::EmptyAccessToken => f.write_str("received empty access token from Tailscale"),
            Self::EmptyAuthKey => f.write_str("received empty authkey from control server"),
            Self::TokenExchange(error) => {
                write!(f, "failed to exchange JWT for access token: {error}")
            }
            Self::CreateAuthKey(error) => {
                write!(f, "unexpected error while creating authkey: {error}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Federation client with injectable network and provider-token dependencies.
#[derive(Clone)]
pub struct FederationClient {
    http: Arc<dyn HttpClient>,
    provider_tokens: Arc<dyn ProviderTokenSource>,
    url_policy: UrlPolicy,
    exchange_timeout: Duration,
    provider_timeout: Duration,
}

impl Default for FederationClient {
    fn default() -> Self {
        let http: Arc<dyn HttpClient> = match ReqwestHttpClient::new() {
            Ok(client) => Arc::new(client),
            Err(_) => Arc::new(UnavailableHttpClient),
        };
        Self::new(http, Arc::new(NoProviderTokenSource))
    }
}

impl FederationClient {
    pub fn new(http: Arc<dyn HttpClient>, provider_tokens: Arc<dyn ProviderTokenSource>) -> Self {
        Self {
            http,
            provider_tokens,
            url_policy: UrlPolicy::HttpsOnly,
            exchange_timeout: DEFAULT_EXCHANGE_TIMEOUT,
            provider_timeout: DEFAULT_PROVIDER_TIMEOUT,
        }
    }

    pub fn with_url_policy(mut self, policy: UrlPolicy) -> Self {
        self.url_policy = policy;
        self
    }

    pub fn with_timeouts(mut self, exchange: Duration, provider: Duration) -> Self {
        self.exchange_timeout = exchange;
        self.provider_timeout = provider;
        self
    }

    /// Resolve a Tailscale OAuth client secret into a tagged, one-use auth key.
    /// Non-client-secret values pass through unchanged, matching upstream.
    pub async fn resolve_oauth_auth_key(
        &self,
        client_secret: &str,
        tags: &[String],
    ) -> Result<String, Error> {
        if !client_secret.starts_with("tskey-client-") {
            return Ok(client_secret.to_owned());
        }
        if tags.is_empty() {
            return Err(Error::MissingOAuthTags);
        }

        let attributes = parse_oauth_secret_attributes(client_secret)
            .map_err(|error| Error::InvalidOptionalAttributes(error.to_string()))?;
        let secret = Zeroizing::new(attributes.client_secret);
        let endpoint = endpoint_url(&attributes.base_url, "/api/v2/oauth/token", self.url_policy)?;
        let authorization = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD
                .encode(format!("some-client-id:{}", secret.as_str()))
        );
        let response = self
            .send(
                HttpRequest {
                    method: "POST",
                    url: endpoint,
                    headers: vec![
                        (
                            "Content-Type".into(),
                            "application/x-www-form-urlencoded".into(),
                        ),
                        ("Authorization".into(), authorization),
                    ],
                    body: form_encode(&[("grant_type", "client_credentials")]),
                },
                MAX_TOKEN_RESPONSE_SIZE,
                "OAuth token exchange",
            )
            .await?;
        let access_token = Zeroizing::new(parse_token_response(response)?);
        if access_token.is_empty() {
            return Err(Error::EmptyAccessToken);
        }
        let auth_key = self
            .create_auth_key(
                &attributes.base_url,
                &access_token,
                attributes.ephemeral,
                attributes.preauthorized,
                tags,
                true,
            )
            .await?;
        if auth_key.is_empty() {
            return Err(Error::EmptyAuthKey);
        }
        Ok(auth_key)
    }

    /// Resolve an ID token into a tagged, one-use auth key.
    pub async fn resolve_auth_key(
        &self,
        base_url: &str,
        client_id: &str,
        id_token: &str,
        audience: &str,
        tags: &[String],
    ) -> Result<String, Error> {
        // Match upstream's package-level no-op. The tsnet integration performs
        // the stricter cross-field validation before invoking this method.
        if client_id.is_empty() {
            return Ok(String::new());
        }

        let token = Zeroizing::new(if id_token.is_empty() {
            if audience.is_empty() {
                return Err(Error::MissingTokenOrAudience);
            }
            match tokio::time::timeout(
                self.provider_timeout,
                self.provider_tokens.token(audience.trim()),
            )
            .await
            {
                Ok(Ok(token)) if !token.trim().is_empty() => token,
                Ok(Ok(_) | Err(_)) | Err(_) => return Err(Error::ProviderTokenRequired),
            }
        } else {
            id_token.to_owned()
        });

        if tags.is_empty() {
            return Err(Error::MissingTags);
        }

        let attributes = parse_optional_attributes(client_id)
            .map_err(|error| Error::InvalidOptionalAttributes(error.to_string()))?;
        let access_token = Zeroizing::new(
            self.exchange_jwt_for_token(base_url, &attributes.client_id, &token)
                .await
                .map_err(|error| Error::TokenExchange(error.to_string()))?,
        );
        if access_token.is_empty() {
            return Err(Error::EmptyAccessToken);
        }

        let auth_key = self
            .create_auth_key(
                base_url,
                &access_token,
                attributes.ephemeral,
                attributes.preauthorized,
                tags,
                false,
            )
            .await
            .map_err(|error| Error::CreateAuthKey(error.to_string()))?;
        if auth_key.is_empty() {
            return Err(Error::EmptyAuthKey);
        }
        Ok(auth_key)
    }

    /// Exchange a provider JWT for a Tailscale access token.
    pub async fn exchange_jwt_for_token(
        &self,
        base_url: &str,
        client_id: &str,
        id_token: &str,
    ) -> Result<String, Error> {
        let endpoint = endpoint_url(base_url, "/api/v2/oauth/token-exchange", self.url_policy)?;
        let body = form_encode(&[
            ("client_id", client_id),
            ("code", ""),
            ("grant_type", "authorization_code"),
            ("jwt", id_token),
        ]);

        // oauth2.Config.Exchange first probes HTTP Basic client auth. Its
        // Config client ID and secret are empty in upstream, yielding `Basic
        // Og==`; the actual federated client ID remains a form parameter.
        let first = self
            .send(
                HttpRequest {
                    method: "POST",
                    url: endpoint.clone(),
                    headers: vec![
                        (
                            "Content-Type".into(),
                            "application/x-www-form-urlencoded".into(),
                        ),
                        ("Authorization".into(), "Basic Og==".into()),
                    ],
                    body: body.clone(),
                },
                MAX_TOKEN_RESPONSE_SIZE,
                "token exchange",
            )
            .await;

        // Match oauth2's unknown-auth-style fallback: retry with credentials
        // in parameters (which removes the empty Basic header) after any
        // retrieval error.
        let response = match first.and_then(parse_token_response) {
            Ok(token) => return Ok(token),
            Err(_) => {
                self.send(
                    HttpRequest {
                        method: "POST",
                        url: endpoint,
                        headers: vec![(
                            "Content-Type".into(),
                            "application/x-www-form-urlencoded".into(),
                        )],
                        body,
                    },
                    MAX_TOKEN_RESPONSE_SIZE,
                    "token exchange",
                )
                .await?
            }
        };
        parse_token_response(response)
    }

    async fn create_auth_key(
        &self,
        base_url: &str,
        access_token: &str,
        ephemeral: bool,
        preauthorized: bool,
        tags: &[String],
        bearer_auth: bool,
    ) -> Result<String, Error> {
        let endpoint = endpoint_url(base_url, "/api/v2/tailnet/-/keys", self.url_policy)?;
        let request = CreateKeyRequest {
            capabilities: KeyCapabilities {
                devices: DeviceCapabilities {
                    create: DeviceCreateCapabilities {
                        reusable: false,
                        ephemeral,
                        preauthorized,
                        tags,
                    },
                },
            },
        };
        let body = serde_json::to_vec(&request)
            .map_err(|_| Error::MalformedResponse("auth key request"))?;
        let authorization = if bearer_auth {
            format!("Bearer {access_token}")
        } else {
            format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{access_token}:"))
            )
        };
        let response = self
            .send(
                HttpRequest {
                    method: "POST",
                    url: endpoint,
                    headers: vec![
                        ("Content-Type".into(), "application/json".into()),
                        ("Authorization".into(), authorization),
                        (
                            "User-Agent".into(),
                            "tailscale-cli-identity-federation".into(),
                        ),
                    ],
                    body,
                },
                MAX_API_RESPONSE_SIZE,
                "auth key creation",
            )
            .await?;
        if response.status != 200 {
            return Err(Error::HttpStatus {
                operation: "auth key creation",
                status: response.status,
            });
        }
        let response: CreateKeyResponse = serde_json::from_slice(&response.body)
            .map_err(|_| Error::MalformedResponse("auth key creation"))?;
        Ok(response.key)
    }

    async fn send(
        &self,
        request: HttpRequest,
        max_size: usize,
        operation: &'static str,
    ) -> Result<HttpResponse, Error> {
        let response = tokio::time::timeout(self.exchange_timeout, self.http.execute(request))
            .await
            .map_err(|_| Error::RequestTimeout(operation))?
            .map_err(|_| Error::RequestFailed(operation))?;
        if response.body.len() > max_size {
            return Err(Error::ResponseTooLarge(operation));
        }
        Ok(response)
    }
}

#[derive(Debug)]
struct UnavailableHttpClient;

#[async_trait]
impl HttpClient for UnavailableHttpClient {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
        Err(HttpError::new("HTTP client unavailable"))
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
    #[serde(default)]
    error_uri: String,
}

fn parse_token_response(mut response: HttpResponse) -> Result<String, Error> {
    let result = parse_token_response_inner(&response);
    response.body.zeroize();
    result
}

fn parse_token_response_inner(response: &HttpResponse) -> Result<String, Error> {
    if !(200..=299).contains(&response.status) {
        return Err(Error::HttpStatus {
            operation: "token exchange",
            status: response.status,
        });
    }
    let media_type = response
        .content_type
        .as_deref()
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let access_token = if matches!(
        media_type.as_str(),
        "application/x-www-form-urlencoded" | "text/plain"
    ) {
        let mut values =
            parse_query(&response.body).map_err(|_| Error::MalformedResponse("token exchange"))?;
        let has_error = values.get("error").is_some_and(|error| !error.is_empty());
        let mut access_token = values.remove("access_token").unwrap_or_default();
        for value in values.values_mut() {
            value.zeroize();
        }
        if has_error {
            access_token.zeroize();
            return Err(Error::OAuthError);
        }
        access_token
    } else {
        let TokenResponse {
            mut access_token,
            mut error,
            mut error_description,
            mut error_uri,
        } = serde_json::from_slice(&response.body)
            .map_err(|_| Error::MalformedResponse("token exchange"))?;
        let has_error = !error.is_empty();
        error.zeroize();
        error_description.zeroize();
        error_uri.zeroize();
        if has_error {
            access_token.zeroize();
            return Err(Error::OAuthError);
        }
        access_token
    };
    if access_token.is_empty() {
        return Err(Error::EmptyAccessToken);
    }
    Ok(access_token)
}

#[derive(Serialize)]
struct CreateKeyRequest<'a> {
    capabilities: KeyCapabilities<'a>,
}

#[derive(Serialize)]
struct KeyCapabilities<'a> {
    devices: DeviceCapabilities<'a>,
}

#[derive(Serialize)]
struct DeviceCapabilities<'a> {
    create: DeviceCreateCapabilities<'a>,
}

#[derive(Serialize)]
struct DeviceCreateCapabilities<'a> {
    reusable: bool,
    ephemeral: bool,
    preauthorized: bool,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    tags: &'a [String],
}

#[derive(Deserialize)]
struct CreateKeyResponse {
    #[serde(default)]
    key: String,
}

fn endpoint_url(base_url: &str, suffix: &str, policy: UrlPolicy) -> Result<Url, Error> {
    let base_url = if base_url.is_empty() {
        DEFAULT_CONTROL_URL.to_owned()
    } else if base_url.contains("://") {
        base_url.to_owned()
    } else {
        format!("https://{base_url}")
    };
    let mut url = Url::parse(&base_url).map_err(|_| Error::UntrustedUrl)?;
    let trustworthy_scheme = match url.scheme() {
        "https" => true,
        "http" if policy == UrlPolicy::HttpsOrLoopbackHttp => url
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback()),
        _ => false,
    };
    if !trustworthy_scheme
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::UntrustedUrl);
    }
    let path = format!("{}{}", url.path().trim_end_matches('/'), suffix);
    url.set_path(&path);
    Ok(url)
}

/// Return the ephemeral-node attribute carried by an OAuth client secret.
/// The value defaults to true, matching Tailscale's OAuth auth-key feature.
pub fn oauth_secret_is_ephemeral(client_secret: &str) -> Result<bool, ParseError> {
    parse_oauth_secret_attributes(client_secret).map(|attributes| attributes.ephemeral)
}

fn parse_oauth_secret_attributes(client_secret: &str) -> Result<OAuthSecretAttributes, ParseError> {
    let (stripped, query) = client_secret
        .split_once('?')
        .map_or((client_secret, ""), |(secret, query)| (secret, query));
    let values = parse_query(query.as_bytes())?;
    let mut ephemeral = true;
    let mut preauthorized = false;
    let mut base_url = DEFAULT_API_URL.to_owned();
    for (key, value) in values {
        match key.as_str() {
            "ephemeral" if !value.is_empty() => ephemeral = parse_bool(&value)?,
            "ephemeral" => {}
            "preauthorized" if !value.is_empty() => preauthorized = parse_bool(&value)?,
            "preauthorized" => {}
            "baseURL" if !value.is_empty() => base_url = value,
            "baseURL" => {}
            _ => return Err(ParseError::UnknownAttribute(key)),
        }
    }
    Ok(OAuthSecretAttributes {
        client_secret: stripped.to_owned(),
        ephemeral,
        preauthorized,
        base_url,
    })
}

/// Parse `?ephemeral=` and `?preauthorized=` attributes from a client ID.
/// Defaults and accepted boolean spellings match Go's implementation.
pub fn parse_optional_attributes(client_id: &str) -> Result<ClientIdAttributes, ParseError> {
    let Some((stripped, attributes)) = client_id.split_once('?') else {
        return Ok(ClientIdAttributes {
            client_id: client_id.to_owned(),
            ephemeral: true,
            preauthorized: false,
        });
    };
    let values = parse_query(attributes.as_bytes())?;
    let mut ephemeral = false;
    let mut preauthorized = false;
    for (key, value) in values {
        match key.as_str() {
            "ephemeral" => ephemeral = parse_bool(&value)?,
            "preauthorized" => preauthorized = parse_bool(&value)?,
            _ => return Err(ParseError::UnknownAttribute(key)),
        }
    }
    Ok(ClientIdAttributes {
        client_id: stripped.to_owned(),
        ephemeral,
        preauthorized,
    })
}

/// Optional client-ID attribute parse failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    MalformedQuery,
    UnknownAttribute(String),
    InvalidBoolean(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedQuery => f.write_str("failed to parse optional config attributes"),
            Self::UnknownAttribute(attribute) => {
                write!(f, "unknown optional config attribute {attribute:?}")
            }
            Self::InvalidBoolean(value) => {
                write!(f, "strconv.ParseBool: parsing {value:?}: invalid syntax")
            }
        }
    }
}

impl std::error::Error for ParseError {}

fn parse_bool(value: &str) -> Result<bool, ParseError> {
    match value {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(ParseError::InvalidBoolean(value.to_owned())),
    }
}

fn form_encode(values: &[(&str, &str)]) -> Vec<u8> {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(values.iter().copied())
        .finish()
        .into_bytes()
}

fn parse_query(query: &[u8]) -> Result<BTreeMap<String, String>, ParseError> {
    let query = std::str::from_utf8(query).map_err(|_| ParseError::MalformedQuery)?;
    if query.as_bytes().contains(&b';') {
        return Err(ParseError::MalformedQuery);
    }
    let mut values = BTreeMap::new();
    if query.is_empty() {
        return Ok(values);
    }
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = decode_query_component(key)?;
        let value = decode_query_component(value)?;
        values.entry(key).or_insert(value);
    }
    Ok(values)
}

fn decode_query_component(value: &str) -> Result<String, ParseError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(ParseError::MalformedQuery);
                }
                let high = hex_value(bytes[index + 1]).ok_or(ParseError::MalformedQuery)?;
                let low = hex_value(bytes[index + 2]).ok_or(ParseError::MalformedQuery)?;
                decoded.push((high << 4) | low);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8(decoded).map_err(|_| ParseError::MalformedQuery)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Feature installation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallError {
    DuplicateFeature,
    OAuthResolverAlreadySet,
    ResolverAlreadySet,
    ExchangerAlreadySet,
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateFeature => f.write_str("identityfederation feature already registered"),
            Self::OAuthResolverAlreadySet => f.write_str("OAuth auth-key resolver already set"),
            Self::ResolverAlreadySet => f.write_str("identity federation resolver already set"),
            Self::ExchangerAlreadySet => f.write_str("identity federation exchanger already set"),
        }
    }
}

impl std::error::Error for InstallError {}

static INSTALL_RESULT: OnceLock<Result<(), InstallError>> = OnceLock::new();

/// Register the package and install its two feature hooks with production
/// defaults. Provider auto-discovery is intentionally unavailable; use
/// [`install_with_client`] before starting tsnet when audience-based token
/// acquisition is required.
pub fn install() -> Result<(), InstallError> {
    install_with_client(FederationClient::default())
}

/// Register the package using an explicitly configured client.
///
/// The first installation wins process-wide, matching single-assignment hook
/// semantics. This is the integration point for injecting workload-platform
/// token sources and hermetic HTTP transports.
pub fn install_with_client(client: FederationClient) -> Result<(), InstallError> {
    *INSTALL_RESULT.get_or_init(move || {
        rustscale_feature::register("identityfederation")
            .map_err(|_| InstallError::DuplicateFeature)?;
        let oauth_client = client.clone();
        rustscale_feature::RESOLVE_AUTH_KEY_VIA_OAUTH
            .set(Arc::new(move |request| {
                let client = oauth_client.clone();
                Box::pin(async move {
                    client
                        .resolve_oauth_auth_key(&request.client_secret, &request.tags)
                        .await
                        .map_err(|error| -> rustscale_feature::BoxError { Box::new(error) })
                })
            }))
            .map_err(|_| InstallError::OAuthResolverAlreadySet)?;
        let resolver_client = client.clone();
        rustscale_feature::RESOLVE_AUTH_KEY_VIA_WIF
            .set(Arc::new(move |request| {
                let client = resolver_client.clone();
                Box::pin(async move {
                    client
                        .resolve_auth_key(
                            &request.base_url,
                            &request.client_id,
                            &request.id_token,
                            &request.audience,
                            &request.tags,
                        )
                        .await
                        .map_err(|error| -> rustscale_feature::BoxError { Box::new(error) })
                })
            }))
            .map_err(|_| InstallError::ResolverAlreadySet)?;
        rustscale_feature::EXCHANGE_JWT_FOR_TOKEN_VIA_WIF
            .set(Arc::new(move |request| {
                let client = client.clone();
                Box::pin(async move {
                    client
                        .exchange_jwt_for_token(
                            &request.base_url,
                            &request.client_id,
                            &request.id_token,
                        )
                        .await
                        .map_err(|error| -> rustscale_feature::BoxError { Box::new(error) })
                })
            }))
            .map_err(|_| InstallError::ExchangerAlreadySet)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests;
