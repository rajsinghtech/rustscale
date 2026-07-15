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
const MAX_REDIRECTS: usize = 5;

pub struct HttpClient {
    client: Client,
}

impl HttpClient {
    pub fn new() -> Result<Self, UpdateError> {
        let redirects = redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                return attempt.error("too many redirects");
            }
            if redirect_url_allowed(attempt.url()) {
                attempt.follow()
            } else {
                attempt.error("redirect target is not an allowed HTTPS GitHub host")
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
        if !initial_url_allowed(&parsed) {
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

fn initial_url_allowed(url: &Url) -> bool {
    if !basic_https_url(url) {
        return false;
    }
    match url.host_str() {
        Some("api.github.com") => {
            url.path() == "/repos/rajsinghtech/rustscale/releases"
                || url
                    .path()
                    .strip_prefix("/repos/rajsinghtech/rustscale/releases/tags/")
                    .is_some_and(valid_tag)
        }
        Some("github.com") => {
            url.query().is_none()
                && url
                    .path()
                    .starts_with("/rajsinghtech/rustscale/releases/download/")
        }
        _ => false,
    }
}

fn redirect_url_allowed(url: &Url) -> bool {
    if !basic_https_url(url) {
        return false;
    }
    matches!(
        url.host_str(),
        Some("api.github.com" | "github.com" | "release-assets.githubusercontent.com")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_credentials_http_and_uncontrolled_hosts() {
        for url in [
            "http://github.com/rajsinghtech/rustscale/releases/download/v1.0.0/a",
            "https://user@github.com/rajsinghtech/rustscale/releases/download/v1.0.0/a",
            "https://example.com/rajsinghtech/rustscale/releases/download/v1.0.0/a",
            "https://github.com.evil/rajsinghtech/rustscale/releases/download/v1.0.0/a",
        ] {
            assert!(!initial_url_allowed(&Url::parse(url).unwrap()));
        }
    }

    #[test]
    fn redirect_hosts_are_narrowly_allowlisted() {
        assert!(redirect_url_allowed(
            &Url::parse("https://release-assets.githubusercontent.com/signed?x=1").unwrap()
        ));
        assert!(!redirect_url_allowed(
            &Url::parse("https://objects.githubusercontent.com/signed").unwrap()
        ));
        assert!(!redirect_url_allowed(
            &Url::parse("http://release-assets.githubusercontent.com/signed").unwrap()
        ));
    }
}
