use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

use super::*;

struct FakeHttp {
    responses: Mutex<VecDeque<Result<HttpResponse, HttpError>>>,
    requests: Mutex<Vec<HttpRequest>>,
}

impl FakeHttp {
    fn new(responses: Vec<HttpResponse>) -> Arc<Self> {
        Arc::new(Self {
            responses: Mutex::new(responses.into_iter().map(Ok).collect()),
            requests: Mutex::new(Vec::new()),
        })
    }

    fn take_requests(&self) -> Vec<HttpRequest> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}

#[async_trait]
impl HttpClient for FakeHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(HttpError::new("no queued response")))
    }
}

#[derive(Default)]
struct FakeProvider {
    result: Mutex<Option<Result<String, ProviderTokenError>>>,
    audiences: Mutex<Vec<String>>,
}

impl FakeProvider {
    fn returning(token: &str) -> Arc<Self> {
        Arc::new(Self {
            result: Mutex::new(Some(Ok(token.to_owned()))),
            audiences: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl ProviderTokenSource for FakeProvider {
    async fn token(&self, audience: &str) -> Result<String, ProviderTokenError> {
        self.audiences.lock().unwrap().push(audience.to_owned());
        self.result
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| Err(ProviderTokenError::new("no token")))
    }
}

fn response(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> HttpResponse {
    HttpResponse {
        status,
        content_type: Some(content_type.to_owned()),
        body: body.into(),
    }
}

fn success_http() -> Arc<FakeHttp> {
    FakeHttp::new(vec![
        response(
            200,
            "application/json",
            br#"{"access_token":"access-123","token_type":"Bearer","expires_in":3600}"#,
        ),
        response(
            200,
            "application/json",
            br#"{"key":"tskey-auth-xyz","created":"2024-01-01T00:00:00Z"}"#,
        ),
    ])
}

fn test_client(http: Arc<dyn HttpClient>) -> FederationClient {
    FederationClient::new(http, Arc::new(NoProviderTokenSource))
        .with_url_policy(UrlPolicy::HttpsOrLoopbackHttp)
}

#[test]
fn parse_optional_attributes_matches_upstream() {
    assert_eq!(
        parse_optional_attributes("client-123").unwrap(),
        ClientIdAttributes {
            client_id: "client-123".into(),
            ephemeral: true,
            preauthorized: false,
        }
    );
    assert_eq!(
        parse_optional_attributes("client-123?ephemeral=false&preauthorized=true").unwrap(),
        ClientIdAttributes {
            client_id: "client-123".into(),
            ephemeral: false,
            preauthorized: true,
        }
    );
    assert_eq!(
        parse_optional_attributes("client-123?").unwrap(),
        ClientIdAttributes {
            client_id: "client-123".into(),
            ephemeral: false,
            preauthorized: false,
        }
    );
    assert_eq!(
        parse_optional_attributes("client?ephemeral=T&preauthorized=0").unwrap(),
        ClientIdAttributes {
            client_id: "client".into(),
            ephemeral: true,
            preauthorized: false,
        }
    );
    assert_eq!(
        parse_optional_attributes("client-123?unknown=value").unwrap_err(),
        ParseError::UnknownAttribute("unknown".into())
    );
    assert_eq!(
        parse_optional_attributes("client-123?ephemeral=invalid").unwrap_err(),
        ParseError::InvalidBoolean("invalid".into())
    );
}

#[test]
fn parse_oauth_secret_attributes_matches_upstream() {
    assert_eq!(
        parse_oauth_secret_attributes("tskey-client-abc").unwrap(),
        OAuthSecretAttributes {
            client_secret: "tskey-client-abc".into(),
            ephemeral: true,
            preauthorized: false,
            base_url: DEFAULT_API_URL.into(),
        }
    );
    assert_eq!(
        parse_oauth_secret_attributes(
            "tskey-client-abc?ephemeral=false&preauthorized=true&baseURL=http%3A%2F%2F127.0.0.1%3A1234"
        )
        .unwrap(),
        OAuthSecretAttributes {
            client_secret: "tskey-client-abc".into(),
            ephemeral: false,
            preauthorized: true,
            base_url: "http://127.0.0.1:1234".into(),
        }
    );
    assert_eq!(
        parse_oauth_secret_attributes("tskey-client-abc?unknown=value").unwrap_err(),
        ParseError::UnknownAttribute("unknown".into())
    );
}

#[tokio::test]
async fn oauth_client_secret_resolves_to_tagged_auth_key() {
    let http = success_http();
    let client = test_client(http.clone());
    let key = client
        .resolve_oauth_auth_key(
            "tskey-client-secret?ephemeral=false&preauthorized=true&baseURL=http%3A%2F%2F127.0.0.1%3A1234",
            &["tag:k8s".into(), "tag:ottawa".into()],
        )
        .await
        .unwrap();
    assert_eq!(key, "tskey-auth-xyz");

    let requests = http.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].url.as_str(),
        "http://127.0.0.1:1234/api/v2/oauth/token"
    );
    assert_eq!(requests[0].body, b"grant_type=client_credentials");
    let expected_basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("some-client-id:tskey-client-secret")
    );
    assert!(requests[0]
        .headers
        .iter()
        .any(|(name, value)| name == "Authorization" && value == &expected_basic));
    assert!(requests[1]
        .headers
        .iter()
        .any(|(name, value)| name == "Authorization" && value == "Bearer access-123"));
    let create: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(
        create["capabilities"]["devices"]["create"]["ephemeral"],
        false
    );
    assert_eq!(
        create["capabilities"]["devices"]["create"]["preauthorized"],
        true
    );
    assert_eq!(
        create["capabilities"]["devices"]["create"]["tags"],
        serde_json::json!(["tag:k8s", "tag:ottawa"])
    );
}

#[tokio::test]
async fn oauth_client_secret_requires_tags_and_plain_auth_keys_pass_through() {
    let client = test_client(FakeHttp::new(vec![]));
    assert_eq!(
        client
            .resolve_oauth_auth_key("tskey-auth-plain", &[])
            .await
            .unwrap(),
        "tskey-auth-plain"
    );
    assert_eq!(
        client
            .resolve_oauth_auth_key("tskey-client-secret", &[])
            .await
            .unwrap_err(),
        Error::MissingOAuthTags
    );
}

#[test]
fn malformed_optional_attributes_fail_closed() {
    for client_id in [
        "client?ephemeral=%",
        "client?ephemeral=%GG",
        "client?ephemeral=true;preauthorized=true",
        "client?%FF=true",
    ] {
        assert_eq!(
            parse_optional_attributes(client_id).unwrap_err(),
            ParseError::MalformedQuery,
            "client ID {client_id}"
        );
    }
}

#[tokio::test]
async fn resolve_auth_key_ports_upstream_cases_and_wire_shapes() {
    let http = success_http();
    let client = test_client(http.clone());
    let tags = vec!["tag:test".to_owned()];
    let auth_key = client
        .resolve_auth_key(
            "http://127.0.0.1:1234",
            "client-123",
            "provider-token",
            "api://tailscale-wif",
            &tags,
        )
        .await
        .unwrap();
    assert_eq!(auth_key, "tskey-auth-xyz");

    let requests = http.take_requests();
    assert_eq!(requests.len(), 2);
    let exchange = &requests[0];
    assert_eq!(exchange.method, "POST");
    assert_eq!(
        exchange.url.as_str(),
        "http://127.0.0.1:1234/api/v2/oauth/token-exchange"
    );
    assert_eq!(
        std::str::from_utf8(&exchange.body).unwrap(),
        "client_id=client-123&code=&grant_type=authorization_code&jwt=provider-token"
    );
    assert!(exchange
        .headers
        .iter()
        .any(|header| header == &("Authorization".into(), "Basic Og==".into())));

    let create = &requests[1];
    assert_eq!(
        create.url.as_str(),
        "http://127.0.0.1:1234/api/v2/tailnet/-/keys"
    );
    assert!(create.headers.iter().any(|header| {
        header
            == &(
                "User-Agent".into(),
                "tailscale-cli-identity-federation".into(),
            )
    }));
    assert!(create
        .headers
        .iter()
        .any(|header| { header == &("Authorization".into(), "Basic YWNjZXNzLTEyMzo=".into(),) }));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&create.body).unwrap(),
        serde_json::json!({
            "capabilities": {
                "devices": {
                    "create": {
                        "reusable": false,
                        "ephemeral": true,
                        "preauthorized": false,
                        "tags": ["tag:test"]
                    }
                }
            }
        })
    );
}

#[tokio::test]
async fn client_id_attributes_control_auth_key_capabilities() {
    let http = success_http();
    let client = test_client(http.clone());
    client
        .resolve_auth_key(
            "http://127.0.0.1:1234",
            "client?ephemeral=false&preauthorized=true",
            "token",
            "",
            &["tag:prod".into()],
        )
        .await
        .unwrap();
    let requests = http.take_requests();
    let body: serde_json::Value = serde_json::from_slice(&requests[1].body).unwrap();
    assert_eq!(
        body["capabilities"]["devices"]["create"]["ephemeral"],
        false
    );
    assert_eq!(
        body["capabilities"]["devices"]["create"]["preauthorized"],
        true
    );
}

#[tokio::test]
async fn resolve_validation_matches_upstream_package() {
    let tags = vec!["tag:test".to_owned()];
    let client = test_client(FakeHttp::new(vec![]));
    assert_eq!(
        client
            .resolve_auth_key("", "", "token", "audience", &tags)
            .await
            .unwrap(),
        ""
    );
    assert_eq!(
        client
            .resolve_auth_key("", "client", "", "", &tags)
            .await
            .unwrap_err()
            .to_string(),
        "federated identity requires either an ID token or an audience"
    );
    assert_eq!(
        client
            .resolve_auth_key("", "client", "token", "", &[])
            .await
            .unwrap_err()
            .to_string(),
        "federated identity authkeys require --advertise-tags"
    );
    assert_eq!(
        client
            .resolve_auth_key("", "client?invalid=value", "token", "", &tags,)
            .await
            .unwrap_err()
            .to_string(),
        "failed to parse optional config attributes: unknown optional config attribute \"invalid\""
    );
}

#[tokio::test]
async fn audience_uses_only_the_injected_provider_source() {
    let http = success_http();
    let provider = FakeProvider::returning("minted-token");
    let client = FederationClient::new(http.clone(), provider.clone())
        .with_url_policy(UrlPolicy::HttpsOrLoopbackHttp);
    client
        .resolve_auth_key(
            "http://127.0.0.1:1234",
            "client",
            "",
            "  api://audience  ",
            &["tag:test".into()],
        )
        .await
        .unwrap();
    assert_eq!(*provider.audiences.lock().unwrap(), ["api://audience"]);
    let requests = http.take_requests();
    assert!(std::str::from_utf8(&requests[0].body)
        .unwrap()
        .contains("jwt=minted-token"));
}

#[tokio::test]
async fn provider_failure_is_generic_and_does_not_leak_source_errors() {
    let provider = Arc::new(FakeProvider {
        result: Mutex::new(Some(Err(ProviderTokenError::new(
            "provider returned bearer secret-provider-token",
        )))),
        audiences: Mutex::new(Vec::new()),
    });
    let client = FederationClient::new(FakeHttp::new(vec![]), provider);
    let error = client
        .resolve_auth_key("", "client", "", "aud", &["tag:test".into()])
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "federated identity authkeys require --id-token");
    assert!(!error.contains("secret-provider-token"));
}

#[tokio::test]
async fn oauth_auth_style_fallback_removes_basic_header() {
    let http = FakeHttp::new(vec![
        response(401, "application/json", br#"{"error":"invalid_client"}"#),
        response(
            200,
            "application/x-www-form-urlencoded",
            b"access_token=second-token&token_type=Bearer".to_vec(),
        ),
    ]);
    let client = test_client(http.clone());
    assert_eq!(
        client
            .exchange_jwt_for_token("http://127.0.0.1:1234", "client", "jwt")
            .await
            .unwrap(),
        "second-token"
    );
    let requests = http.take_requests();
    assert!(requests[0]
        .headers
        .iter()
        .any(|(name, _)| name == "Authorization"));
    assert!(!requests[1]
        .headers
        .iter()
        .any(|(name, _)| name == "Authorization"));
    assert_eq!(requests[0].body, requests[1].body);
}

#[tokio::test]
async fn oauth_2xx_errors_are_rejected_and_sanitized() {
    let http = FakeHttp::new(vec![
        response(
            200,
            "application/json",
            br#"{"error":"invalid_grant","error_description":"secret-jwt","error_uri":"https://errors.example/secret","access_token":"must-not-win"}"#,
        ),
        response(
            200,
            "application/json",
            br#"{"access_token":"fallback-token"}"#,
        ),
    ]);
    let client = test_client(http.clone());
    assert_eq!(
        client
            .exchange_jwt_for_token("http://127.0.0.1:1234", "client", "secret-jwt")
            .await
            .unwrap(),
        "fallback-token"
    );
    assert_eq!(http.take_requests().len(), 2);

    let http = FakeHttp::new(vec![
        response(
            200,
            "application/json",
            br#"{"error":"first-secret","error_description":"secret-jwt","error_uri":"https://errors.example/secret"}"#,
        ),
        response(
            200,
            "application/x-www-form-urlencoded",
            b"error=second-secret&error_description=secret-access-token&error_uri=https%3A%2F%2Ferrors.example%2Fsecret&access_token=must-not-win".to_vec(),
        ),
    ]);
    let client = test_client(http.clone());
    let error = client
        .exchange_jwt_for_token("http://127.0.0.1:1234", "client", "secret-jwt")
        .await
        .unwrap_err();
    assert_eq!(error, Error::OAuthError);
    let displayed = error.to_string();
    let debug = format!("{error:?}");
    assert_eq!(displayed, "token exchange returned an OAuth error");
    assert_eq!(debug, "OAuthError");
    for secret in [
        "first-secret",
        "second-secret",
        "secret-jwt",
        "secret-access-token",
        "must-not-win",
    ] {
        assert!(!displayed.contains(secret));
        assert!(!debug.contains(secret));
    }
    assert_eq!(http.take_requests().len(), 2);
}

#[tokio::test]
async fn empty_access_token_triggers_fallback_and_then_fails_closed() {
    let http = FakeHttp::new(vec![
        response(200, "application/json", br#"{"access_token":""}"#),
        response(
            200,
            "application/x-www-form-urlencoded",
            b"access_token=fallback-token".to_vec(),
        ),
    ]);
    let client = test_client(http.clone());
    assert_eq!(
        client
            .exchange_jwt_for_token("http://127.0.0.1:1234", "client", "jwt")
            .await
            .unwrap(),
        "fallback-token"
    );
    assert_eq!(http.take_requests().len(), 2);

    let http = FakeHttp::new(vec![
        response(200, "application/json", br#"{"access_token":""}"#),
        response(200, "text/plain", b"access_token=".to_vec()),
    ]);
    let client = test_client(http);
    assert_eq!(
        client
            .exchange_jwt_for_token("http://127.0.0.1:1234", "client", "jwt")
            .await
            .unwrap_err(),
        Error::EmptyAccessToken
    );
}

#[tokio::test]
async fn untrusted_control_urls_are_rejected_before_http() {
    let http = FakeHttp::new(vec![]);
    let client = FederationClient::new(http.clone(), Arc::new(NoProviderTokenSource));
    for url in [
        "http://control.example.com",
        "ftp://control.example.com",
        "https://user:password@control.example.com",
        "https://control.example.com?redirect=evil",
        "https://control.example.com#fragment",
    ] {
        assert_eq!(
            client
                .exchange_jwt_for_token(url, "client", "token")
                .await
                .unwrap_err(),
            Error::UntrustedUrl,
            "URL {url}"
        );
    }
    assert!(http.take_requests().is_empty());
}

#[tokio::test]
async fn empty_auth_keys_fail_closed() {
    let http = FakeHttp::new(vec![
        response(
            200,
            "application/json",
            br#"{"access_token":"access-token"}"#,
        ),
        response(200, "application/json", br#"{"key":""}"#),
    ]);
    let client = test_client(http);
    assert_eq!(
        client
            .resolve_auth_key(
                "http://127.0.0.1:1234",
                "client",
                "jwt",
                "",
                &["tag:test".into()],
            )
            .await
            .unwrap_err(),
        Error::EmptyAuthKey
    );
}

#[tokio::test]
async fn oversized_and_error_responses_do_not_leak_tokens() {
    let oversized = vec![b'x'; MAX_TOKEN_RESPONSE_SIZE + 1];
    let http = FakeHttp::new(vec![
        response(200, "application/json", oversized.clone()),
        response(200, "application/json", oversized),
    ]);
    let client = test_client(http);
    assert_eq!(
        client
            .exchange_jwt_for_token("http://127.0.0.1:1234", "client", "secret-jwt")
            .await
            .unwrap_err(),
        Error::ResponseTooLarge("token exchange")
    );

    let secret_body = br#"{"error":"secret-jwt secret-access-token"}"#;
    let http = FakeHttp::new(vec![
        response(401, "application/json", secret_body),
        response(401, "application/json", secret_body),
    ]);
    let client = test_client(http);
    let error = client
        .exchange_jwt_for_token("http://127.0.0.1:1234", "client", "secret-jwt")
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(error, "token exchange failed with status 401");
    assert!(!error.contains("secret-jwt"));
    assert!(!error.contains("secret-access-token"));

    let http = FakeHttp::new(vec![
        response(
            200,
            "application/json",
            br#"{"access_token":"access-token"}"#,
        ),
        response(
            200,
            "application/json",
            vec![b'x'; MAX_API_RESPONSE_SIZE + 1],
        ),
    ]);
    let client = test_client(http);
    let error = client
        .resolve_auth_key(
            "http://127.0.0.1:1234",
            "client",
            "secret-jwt",
            "",
            &["tag:test".into()],
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "unexpected error while creating authkey: auth key creation response too large"
    );
    assert!(!error.contains("secret-jwt"));
    assert!(!error.contains("access-token"));
}

struct PendingProvider;

#[async_trait]
impl ProviderTokenSource for PendingProvider {
    async fn token(&self, _audience: &str) -> Result<String, ProviderTokenError> {
        std::future::pending().await
    }
}

struct PendingHttp;

#[async_trait]
impl HttpClient for PendingHttp {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, HttpError> {
        std::future::pending().await
    }
}

#[tokio::test]
async fn requests_have_a_deadline() {
    let client = FederationClient::new(Arc::new(PendingHttp), Arc::new(NoProviderTokenSource))
        .with_url_policy(UrlPolicy::HttpsOrLoopbackHttp)
        .with_timeouts(Duration::from_millis(5), Duration::from_millis(5));
    assert_eq!(
        client
            .exchange_jwt_for_token("http://127.0.0.1:1234", "client", "token")
            .await
            .unwrap_err(),
        Error::RequestTimeout("token exchange")
    );

    let client = FederationClient::new(FakeHttp::new(vec![]), Arc::new(PendingProvider))
        .with_timeouts(Duration::from_millis(5), Duration::from_millis(5));
    assert_eq!(
        client
            .resolve_auth_key("", "client", "", "aud", &["tag:test".into()])
            .await
            .unwrap_err(),
        Error::ProviderTokenRequired
    );
}

#[test]
fn install_registers_feature_and_hooks() {
    install().unwrap();
    assert!(rustscale_feature::is_registered("identityfederation"));
    assert!(rustscale_feature::RESOLVE_AUTH_KEY_VIA_WIF.is_set());
    assert!(rustscale_feature::EXCHANGE_JWT_FOR_TOKEN_VIA_WIF.is_set());
}
