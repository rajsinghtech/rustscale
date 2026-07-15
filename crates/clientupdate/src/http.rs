use std::io::Read;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, Response};
use reqwest::redirect;
use reqwest::Url;
use sha2::{Digest, Sha256};

use crate::{
    parse_github_release, parse_github_releases, Download, Downloader, GitHubRelease,
    ReleaseLookup, UpdateError, GITHUB_RELEASES_API,
};

const MAX_RELEASE_JSON: usize = 4 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(20);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(90);
// Public immutable GitHub repository ID for rajsinghtech/rustscale. GitHub's
// signed release CDN path uses this ID rather than the repository name.
const RUSTSCALE_REPOSITORY_ID: &str = "1294484547";

pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    pub fn new() -> Result<Self, UpdateError> {
        let redirects = redirect::Policy::custom(|attempt| {
            if redirect_allowed(attempt.previous(), attempt.url()) {
                attempt.follow()
            } else {
                attempt.error("redirect does not match the original RustScale release asset")
            }
        });
        let client = Client::builder()
            .user_agent(concat!("rustscale/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(OVERALL_TIMEOUT)
            .redirect(redirects)
            .build()
            .map_err(|error| UpdateError::Download(error.to_string()))?;
        Ok(Self { client })
    }

    fn fetch(&self, url: &str, max_size: usize) -> Result<Download, UpdateError> {
        let parsed = Url::parse(url)
            .map_err(|error| UpdateError::Download(format!("invalid URL {url:?}: {error}")))?;
        if classify_initial_url(&parsed).is_none() {
            return Err(UpdateError::Download(format!(
                "refusing untrusted download URL {url:?}"
            )));
        }
        let start = Instant::now();
        let response = self
            .client
            .get(parsed)
            .send()
            .and_then(Response::error_for_status)
            .map_err(|error| UpdateError::Download(format!("{url}: {error}")))?;
        if response
            .content_length()
            .is_some_and(|length| length > max_size as u64)
        {
            return Err(UpdateError::Download(format!(
                "response from {url} exceeds the {max_size}-byte limit"
            )));
        }
        read_bounded(response, url, max_size, start)
    }
}

impl Downloader for HttpClient {
    fn download(&self, url: &str, max_size: usize) -> Result<Download, UpdateError> {
        self.fetch(url, max_size)
    }
}

impl ReleaseLookup for HttpClient {
    fn releases(&self) -> Result<Vec<GitHubRelease>, UpdateError> {
        parse_github_releases(&self.fetch(GITHUB_RELEASES_API, MAX_RELEASE_JSON)?.bytes)
    }

    fn release_by_tag(&self, tag: &str) -> Result<GitHubRelease, UpdateError> {
        if !valid_tag(tag) {
            return Err(UpdateError::InvalidVersion(tag.to_owned()));
        }
        let url =
            format!("https://api.github.com/repos/rajsinghtech/rustscale/releases/tags/{tag}");
        parse_github_release(&self.fetch(&url, MAX_RELEASE_JSON)?.bytes)
    }
}

fn read_bounded(
    mut response: Response,
    url: &str,
    max_size: usize,
    start: Instant,
) -> Result<Download, UpdateError> {
    let capacity = response.content_length().unwrap_or(0).min(max_size as u64) as usize;
    let (sender, receiver) = mpsc::sync_channel::<Result<Vec<u8>, String>>(1);
    thread::spawn(move || {
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            match response.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if sender.send(Ok(buffer[..count].to_vec())).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(error.to_string()));
                    return;
                }
            }
        }
    });

    let mut bytes = Vec::with_capacity(capacity);
    let mut hasher = Sha256::new();
    loop {
        let remaining = OVERALL_TIMEOUT.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Err(UpdateError::Download(format!(
                "overall download timeout exceeded for {url}"
            )));
        }
        match receiver.recv_timeout(READ_TIMEOUT.min(remaining)) {
            Ok(Ok(chunk)) => {
                if bytes.len().saturating_add(chunk.len()) > max_size {
                    return Err(UpdateError::Download(format!(
                        "response from {url} exceeds the {max_size}-byte limit"
                    )));
                }
                hasher.update(&chunk);
                bytes.extend_from_slice(&chunk);
            }
            Ok(Err(error)) => {
                return Err(UpdateError::Download(format!("{url}: {error}")));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(UpdateError::Download(format!(
                    "read timeout exceeded for {url}"
                )));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(Download {
        bytes,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn valid_tag(tag: &str) -> bool {
    tag.strip_prefix('v')
        .and_then(|version| semver::Version::parse(version).ok())
        .is_some_and(|version| tag == format!("v{version}"))
}

fn basic_https_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.fragment().is_none()
}

#[derive(Debug, PartialEq, Eq)]
enum InitialRequest {
    Api,
    Asset { tag: String, name: String },
}

fn classify_initial_url(url: &Url) -> Option<InitialRequest> {
    if !basic_https_url(url) {
        return None;
    }
    match url.host_str()? {
        "api.github.com" => {
            let list = url.path() == "/repos/rajsinghtech/rustscale/releases"
                && url.query() == Some("per_page=100");
            let tag = url
                .path()
                .strip_prefix("/repos/rajsinghtech/rustscale/releases/tags/")
                .is_some_and(valid_tag)
                && url.query().is_none();
            (list || tag).then_some(InitialRequest::Api)
        }
        "github.com" => {
            if url.query().is_some() {
                return None;
            }
            let segments: Vec<_> = url.path_segments()?.collect();
            if segments.len() != 6
                || segments[..4] != ["rajsinghtech", "rustscale", "releases", "download"]
                || !valid_tag(segments[4])
                || !valid_asset_name(segments[5])
            {
                return None;
            }
            Some(InitialRequest::Asset {
                tag: segments[4].to_owned(),
                name: segments[5].to_owned(),
            })
        }
        _ => None,
    }
}

fn valid_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// GitHub release assets make one redirect from the canonical browser URL to
/// a signed Azure-backed URL on release-assets.githubusercontent.com. The CDN
/// URL does not encode the release tag, so the trusted tag binding is the
/// single-hop HTTPS transition from the already validated original URL. The
/// repository ID and content-disposition then bind the CDN object to this
/// repository and requested asset name.
fn redirect_allowed(previous: &[Url], next: &Url) -> bool {
    if previous.len() != 1 {
        return false;
    }
    let Some(InitialRequest::Asset { tag, name }) = classify_initial_url(&previous[0]) else {
        return false;
    };
    valid_tag(&tag) && valid_release_cdn_url(next, &name)
}

fn valid_release_cdn_url(url: &Url, asset_name: &str) -> bool {
    if !basic_https_url(url) || url.host_str() != Some("release-assets.githubusercontent.com") {
        return false;
    }
    let Some(segments) = url.path_segments().map(Iterator::collect::<Vec<_>>) else {
        return false;
    };
    if segments.len() != 3
        || segments[0] != "github-production-release-asset"
        || segments[1] != RUSTSCALE_REPOSITORY_ID
        || !valid_cdn_object_id(segments[2])
    {
        return false;
    }

    let mut keys = std::collections::BTreeSet::new();
    let mut filename_matches = false;
    let mut signed = false;
    for (key, value) in url.query_pairs() {
        if !allowed_cdn_query_key(&key) || !keys.insert(key.to_string()) {
            return false;
        }
        match key.as_ref() {
            "rscd" | "response-content-disposition" => {
                filename_matches |= disposition_matches(&value, asset_name);
            }
            "sig" | "jwt" if !value.is_empty() => signed = true,
            "spr" if value != "https" => return false,
            "sr" if value != "b" => return false,
            "sp" if !value.contains('r') => return false,
            _ => {}
        }
    }
    filename_matches && signed
}

fn valid_cdn_object_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn allowed_cdn_query_key(key: &str) -> bool {
    matches!(
        key,
        "sp" | "st"
            | "se"
            | "spr"
            | "sv"
            | "sr"
            | "skoid"
            | "sktid"
            | "skt"
            | "ske"
            | "sks"
            | "skv"
            | "sig"
            | "sip"
            | "si"
            | "sdd"
            | "ses"
            | "rscc"
            | "rscd"
            | "rsce"
            | "rscl"
            | "rsct"
            | "jwt"
            | "response-content-disposition"
            | "response-content-type"
    )
}

fn disposition_matches(value: &str, asset_name: &str) -> bool {
    let value = value.trim();
    [
        format!("attachment; filename={asset_name}"),
        format!("attachment; filename=\"{asset_name}\""),
    ]
    .iter()
    .any(|expected| value == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset_url(tag: &str, name: &str) -> Url {
        Url::parse(&format!(
            "https://github.com/rajsinghtech/rustscale/releases/download/{tag}/{name}"
        ))
        .unwrap()
    }

    fn cdn_url(repository_id: &str, name: &str) -> Url {
        Url::parse(&format!(
            "https://release-assets.githubusercontent.com/github-production-release-asset/{repository_id}/01234567-89ab-cdef-0123-456789abcdef?sp=r&spr=https&sv=2025-01-05&sr=b&rscd=attachment%3B%20filename%3D{name}&rsct=application%2Foctet-stream&sig=signed"
        ))
        .unwrap()
    }

    #[test]
    fn initial_requests_are_exact_repository_tag_and_asset_urls() {
        assert!(matches!(
            classify_initial_url(&asset_url("v1.2.3", "SHA256SUMS")),
            Some(InitialRequest::Asset { .. })
        ));
        assert!(matches!(
            classify_initial_url(&Url::parse(GITHUB_RELEASES_API).unwrap()),
            Some(InitialRequest::Api)
        ));
        for url in [
            "http://github.com/rajsinghtech/rustscale/releases/download/v1.2.3/SHA256SUMS",
            "https://user@github.com/rajsinghtech/rustscale/releases/download/v1.2.3/SHA256SUMS",
            "https://github.com/other/rustscale/releases/download/v1.2.3/SHA256SUMS",
            "https://github.com/rajsinghtech/other/releases/download/v1.2.3/SHA256SUMS",
            "https://github.com/rajsinghtech/rustscale/releases/download/not-a-tag/SHA256SUMS",
            "https://github.com/rajsinghtech/rustscale/releases/download/v1.2.3/SHA256SUMS?other=1",
            "https://api.github.com/repos/rajsinghtech/rustscale/releases?per_page=99",
        ] {
            assert!(classify_initial_url(&Url::parse(url).unwrap()).is_none());
        }
    }

    #[test]
    fn allows_only_bound_single_hop_release_asset_cdn_redirect() {
        let original = asset_url("v1.2.3", "rustscale-x86_64-unknown-linux-gnu.tar.gz");
        let cdn = cdn_url(
            RUSTSCALE_REPOSITORY_ID,
            "rustscale-x86_64-unknown-linux-gnu.tar.gz",
        );
        assert!(redirect_allowed(std::slice::from_ref(&original), &cdn));

        // A second hop is never part of GitHub's canonical release download.
        assert!(!redirect_allowed(&[original.clone(), cdn.clone()], &cdn));
        // Cross-repository CDN objects and filename substitutions are rejected.
        assert!(!redirect_allowed(
            std::slice::from_ref(&original),
            &cdn_url("999999", "rustscale-x86_64-unknown-linux-gnu.tar.gz")
        ));
        assert!(!redirect_allowed(
            std::slice::from_ref(&original),
            &cdn_url(RUSTSCALE_REPOSITORY_ID, "SHA256SUMS")
        ));
    }

    #[test]
    fn rejects_cross_tag_api_transitions_and_modified_cdn_urls() {
        let asset = asset_url("v1.2.3", "SHA256SUMS");
        let api = Url::parse(GITHUB_RELEASES_API).unwrap();
        let cdn = cdn_url(RUSTSCALE_REPOSITORY_ID, "SHA256SUMS");
        assert!(!redirect_allowed(
            std::slice::from_ref(&asset),
            &asset_url("v1.2.4", "SHA256SUMS")
        ));
        assert!(!redirect_allowed(std::slice::from_ref(&asset), &api));
        assert!(!redirect_allowed(std::slice::from_ref(&api), &cdn));

        for url in [
            cdn.as_str().replace("https://", "http://"),
            cdn.as_str().replace(
                "release-assets.githubusercontent.com",
                "user@release-assets.githubusercontent.com",
            ),
            cdn.as_str()
                .replace("github-production-release-asset", "other-path"),
            format!("{}&unexpected=value", cdn.as_str()),
            cdn.as_str()
                .replace("filename%3DSHA256SUMS", "filename%3Dother"),
            cdn.as_str().replace("sig=signed", "sig="),
            cdn.as_str().replace("spr=https", "spr=http"),
        ] {
            assert!(
                !redirect_allowed(std::slice::from_ref(&asset), &Url::parse(&url).unwrap()),
                "accepted redirect {url}"
            );
        }
    }

    #[test]
    fn accepts_github_jwt_signed_cdn_variant() {
        let original = asset_url("v1.2.3", "SHA256SUMS");
        let cdn = Url::parse(
            "https://release-assets.githubusercontent.com/github-production-release-asset/1294484547/01234567-89ab-cdef-0123-456789abcdef?jwt=signed&response-content-disposition=attachment%3B%20filename%3DSHA256SUMS&response-content-type=application%2Foctet-stream",
        )
        .unwrap();
        assert!(redirect_allowed(std::slice::from_ref(&original), &cdn));
    }
}
