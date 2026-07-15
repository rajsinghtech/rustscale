use std::path::Path;

use rustscale_key::{MachinePrivate, MachinePublic, NodePrivate};
use serde::{Deserialize, Serialize};

/// Coordination server identity persisted with node credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerInfo {
    #[serde(default, rename = "server_url")]
    pub url: String,
    #[serde(default, rename = "server_key")]
    pub key: MachinePublic,
}

/// Private node credentials and the coordination server they belong to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeFile {
    #[serde(default = "zero_node_private", rename = "node_key")]
    pub node_key: NodePrivate,
    #[serde(default = "zero_machine_private", rename = "machine_key")]
    pub machine_key: MachinePrivate,
    #[serde(flatten)]
    pub server: ServerInfo,
}

fn zero_node_private() -> NodePrivate {
    NodePrivate::from_raw32([0; 32])
}

fn zero_machine_private() -> MachinePrivate {
    MachinePrivate::from_raw32([0; 32])
}

#[derive(Debug, thiserror::Error)]
pub enum NodeFileError {
    #[error("node_key is missing")]
    MissingNodeKey,
    #[error("machine_key is missing")]
    MissingMachineKey,
    #[error("server_url is missing")]
    MissingServerUrl,
    #[error("server_key is missing")]
    MissingServerKey,
    #[error("reading node file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parsing node file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("writing node file {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl NodeFile {
    /// Validate all required fields, reporting the first missing field.
    pub fn check(&self) -> Result<(), NodeFileError> {
        if self.node_key.is_zero() {
            return Err(NodeFileError::MissingNodeKey);
        }
        if self.machine_key.is_zero() {
            return Err(NodeFileError::MissingMachineKey);
        }
        if self.server.url.is_empty() {
            return Err(NodeFileError::MissingServerUrl);
        }
        if self.server.key.is_zero() {
            return Err(NodeFileError::MissingServerKey);
        }
        Ok(())
    }

    /// Pretty-printed Go-compatible JSON terminated by a newline.
    pub fn as_json(&self) -> Vec<u8> {
        let mut output = serde_json::to_vec_pretty(self)
            .expect("NodeFile contains only infallibly serializable fields");
        output.push(b'\n');
        output
    }

    /// Read and parse a node file. Like Go's `ReadNodeFile`, this does not
    /// reject zero fields; call [`check`](Self::check) when validation is needed.
    pub fn read(path: impl AsRef<Path>) -> Result<Self, NodeFileError> {
        let path = path.as_ref();
        let display = path.display().to_string();
        let data = std::fs::read(path).map_err(|source| NodeFileError::Read {
            path: display.clone(),
            source,
        })?;
        serde_json::from_slice(&data).map_err(|source| NodeFileError::Parse {
            path: display,
            source,
        })
    }

    /// Validate and atomically write a node file with mode 0600 on Unix.
    /// Replacing an existing file also repairs overly broad permissions.
    pub fn write(&self, path: impl AsRef<Path>) -> Result<(), NodeFileError> {
        self.check()?;
        let path = path.as_ref();
        let display = path.display().to_string();
        rustscale_atomicfile::write(path, &self.as_json()).map_err(|source| NodeFileError::Write {
            path: display,
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_JSON: &str = r#"{
  "node_key": "privkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "machine_key": "privkey:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
  "server_url": "https://controlplane.tailscale.com",
  "server_key": "mkey:1111111111111111111111111111111111111111111111111111111111111111"
}"#;

    fn valid_file() -> NodeFile {
        NodeFile {
            node_key: NodePrivate::generate(),
            machine_key: MachinePrivate::generate(),
            server: ServerInfo {
                url: "https://controlplane.tailscale.com".into(),
                key: MachinePrivate::generate().public(),
            },
        }
    }

    #[test]
    fn fixed_go_format_parses_and_writes_same_fields() {
        let file: NodeFile = serde_json::from_str(FIXED_JSON).unwrap();
        file.check().unwrap();
        let encoded = file.as_json();
        assert_eq!(encoded, format!("{FIXED_JSON}\n").as_bytes());
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 4);
        for field in ["node_key", "machine_key", "server_url", "server_key"] {
            assert!(object.contains_key(field), "missing {field}");
        }
        assert!(file.as_json().ends_with(b"\n"));
    }

    #[test]
    fn round_trip_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.json");
        let wanted = valid_file();
        wanted.write(&path).unwrap();
        assert_eq!(NodeFile::read(&path).unwrap(), wanted);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn overwrite_repairs_unsafe_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.json");
        std::fs::write(&path, b"old secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        valid_file().write(&path).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn validation_reports_fields_in_go_order() {
        let mut file = valid_file();
        file.node_key = NodePrivate::from_raw32([0; 32]);
        assert!(matches!(file.check(), Err(NodeFileError::MissingNodeKey)));

        file.node_key = NodePrivate::generate();
        file.machine_key = MachinePrivate::from_raw32([0; 32]);
        assert!(matches!(
            file.check(),
            Err(NodeFileError::MissingMachineKey)
        ));

        file.machine_key = MachinePrivate::generate();
        file.server.url.clear();
        assert!(matches!(file.check(), Err(NodeFileError::MissingServerUrl)));

        file.server.url = "https://example.test".into();
        file.server.key = MachinePublic::default();
        assert!(matches!(file.check(), Err(NodeFileError::MissingServerKey)));
    }

    #[test]
    fn read_accepts_missing_fields_but_rejects_malformed_keys_and_json() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.json");
        std::fs::write(&missing, "{}").unwrap();
        assert!(NodeFile::read(&missing).unwrap().check().is_err());

        for (name, contents) in [
            ("bad-json", "{"),
            (
                "bad-key",
                r#"{"node_key":"private:bad","machine_key":"privkey:0000000000000000000000000000000000000000000000000000000000000000","server_url":"x","server_key":"mkey:0000000000000000000000000000000000000000000000000000000000000000"}"#,
            ),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, contents).unwrap();
            assert!(matches!(
                NodeFile::read(path),
                Err(NodeFileError::Parse { .. })
            ));
        }
    }

    #[test]
    fn write_rejects_invalid_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut file = valid_file();
        file.server.url.clear();
        assert!(matches!(
            file.write(dir.path().join("node.json")),
            Err(NodeFileError::MissingServerUrl)
        ));
    }
}
