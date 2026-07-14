use std::{
    fmt, io,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs},
};

/// A logical address in an in-memory network.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MemAddr(String);

impl MemAddr {
    /// Creates a logical in-memory address from `name`.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self(name.to_owned())
    }

    /// Returns the logical address name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the name of this address family.
    #[must_use]
    pub const fn network(&self) -> &'static str {
        "mem"
    }
}

impl fmt::Display for MemAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl ToSocketAddrs for MemAddr {
    type Iter = std::array::IntoIter<SocketAddr, 1>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        Ok([SocketAddr::from((Ipv4Addr::LOCALHOST, 0))].into_iter())
    }
}
