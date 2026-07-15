use std::{fmt, io, net::SocketAddr, str::FromStr};

/// The address reported by an in-memory connection or listener.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MemAddr {
    text: String,
    network: AddressNetwork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum AddressNetwork {
    Mem,
    Tcp,
}

impl MemAddr {
    /// Creates a logical address whose network name is `mem`.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            text: name.into(),
            network: AddressNetwork::Mem,
        }
    }

    pub(crate) fn tcp(address: SocketAddr) -> Self {
        Self {
            text: address.to_string(),
            network: AddressNetwork::Tcp,
        }
    }

    /// Returns the address text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns `mem` for logical addresses and `tcp` for addresses supplied to
    /// [`crate::MemConn::new_tcp_pair`].
    #[must_use]
    pub const fn network(&self) -> &'static str {
        match self.network {
            AddressNetwork::Mem => "mem",
            AddressNetwork::Tcp => "tcp",
        }
    }

    /// Returns the socket address when this is a TCP address.
    #[must_use]
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        (self.network == AddressNetwork::Tcp)
            .then(|| SocketAddr::from_str(&self.text).ok())
            .flatten()
    }
}

impl fmt::Display for MemAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.text.fmt(formatter)
    }
}

impl FromStr for MemAddr {
    type Err = io::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "memnet address is empty",
            ));
        }
        Ok(Self::new(value))
    }
}
