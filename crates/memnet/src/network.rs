use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::{Arc, RwLock, Weak},
};

use crate::{listener::validate_network, MemConn, MemListener};

const FIRST_EPHEMERAL_PORT: u16 = 33_000;

/// A concurrency-safe registry of in-memory TCP listeners.
///
/// Clones refer to the same registry. Dropping the final `Network` closes all
/// registered listeners, waking their pending accepts and dials.
#[derive(Clone, Default)]
pub struct Network {
    registry: Arc<Registry>,
}

#[derive(Default)]
struct Registry {
    listeners: RwLock<HashMap<String, Arc<MemListener>>>,
}

impl Network {
    /// Creates an empty in-memory network.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds a numeric IP socket address.
    ///
    /// Port zero deterministically chooses the first free port at or above
    /// 33000. The accepted network names are `tcp`, `tcp4`, and `tcp6`.
    pub fn listen(&self, network: &str, address: &str) -> io::Result<Arc<MemListener>> {
        validate_network(network).map_err(|_| {
            io::Error::new(
                ErrorKind::Unsupported,
                format!("memnet listen called with unsupported network {network:?}"),
            )
        })?;
        let socket_addr = address.parse::<SocketAddr>().map_err(|error| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!("memnet listen called with invalid address {address:?}: {error}"),
            )
        })?;

        let mut listeners = self
            .registry
            .listeners
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = if socket_addr.port() == 0 {
            allocate_address(socket_addr, &listeners)?
        } else {
            socket_addr.to_string()
        };
        if listeners.contains_key(&key) {
            return Err(io::Error::new(
                ErrorKind::AddrInUse,
                format!("memnet address {address:?} is already in use"),
            ));
        }

        let listener = Arc::new(MemListener::listen(&key));
        listener.set_on_close(remove_callback(&self.registry, &key, &listener));
        listeners.insert(key, Arc::clone(&listener));
        Ok(listener)
    }

    /// Connects to a listener bound at `address`.
    pub async fn dial(&self, network: &str, address: &str) -> io::Result<MemConn> {
        validate_network(network).map_err(|_| {
            io::Error::new(
                ErrorKind::Unsupported,
                format!("memnet dial called with unsupported network {network:?}"),
            )
        })?;
        let listener = self
            .registry
            .listeners
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(address)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::NotFound,
                    format!("memnet dial called on unknown address {address:?}"),
                )
            })?;
        listener.dial(network, address).await
    }

    /// Creates a listener at the first free `127.0.0.1` test port.
    ///
    /// This can only panic if all ports from 33000 through 65535 are occupied.
    #[must_use]
    pub fn new_local_tcp_listener(&self) -> Arc<MemListener> {
        self.listen("tcp", "127.0.0.1:0")
            .expect("failed to allocate local memnet listener")
    }

    /// Returns the number of currently registered listeners.
    #[must_use]
    pub fn listener_count(&self) -> usize {
        self.registry
            .listeners
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        let listeners = self
            .listeners
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for listener in listeners.values() {
            listener.close();
        }
        listeners.clear();
    }
}

fn allocate_address(
    base: SocketAddr,
    listeners: &HashMap<String, Arc<MemListener>>,
) -> io::Result<String> {
    for port in FIRST_EPHEMERAL_PORT..=u16::MAX {
        let candidate = SocketAddr::new(base.ip(), port).to_string();
        if !listeners.contains_key(&candidate) {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        ErrorKind::AddrNotAvailable,
        "memnet ephemeral port range is exhausted",
    ))
}

fn remove_callback(
    registry: &Arc<Registry>,
    key: &str,
    listener: &Arc<MemListener>,
) -> Box<dyn FnOnce() + Send + 'static> {
    let registry = Arc::downgrade(registry);
    let key = key.to_owned();
    let listener = Arc::downgrade(listener);
    Box::new(move || remove_listener(&registry, &key, &listener))
}

fn remove_listener(registry: &Weak<Registry>, key: &str, listener: &Weak<MemListener>) {
    let Some(registry) = registry.upgrade() else {
        return;
    };
    let mut listeners = registry
        .listeners
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if listeners
        .get(key)
        .is_some_and(|current| Weak::ptr_eq(&Arc::downgrade(current), listener))
    {
        listeners.remove(key);
    }
}
