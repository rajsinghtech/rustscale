use std::{
    collections::HashMap,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock, Weak,
    },
};

use crate::{MemConn, MemListener};

/// A registry of in-memory listeners, addressed by logical names.
#[derive(Clone)]
pub struct Network {
    listeners: Arc<RwLock<HashMap<String, Arc<MemListener>>>>,
    next_port: Arc<AtomicUsize>,
}

impl Default for Network {
    fn default() -> Self {
        Self::new()
    }
}

impl Network {
    /// Creates an empty in-memory network.
    #[must_use]
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(RwLock::new(HashMap::new())),
            next_port: Arc::new(AtomicUsize::new(33_000)),
        }
    }

    /// Binds `address` in this network.
    pub async fn listen(&self, address: &str) -> io::Result<Arc<MemListener>> {
        tokio::task::yield_now().await;
        self.listen_inner(address)
    }

    /// Connects to a listener previously bound at `address`.
    pub async fn dial(&self, address: &str) -> io::Result<MemConn> {
        let listener = self
            .listeners
            .read()
            .expect("network registry lock poisoned")
            .get(address)
            .cloned()
            .ok_or_else(|| io::Error::new(ErrorKind::NotFound, "unknown memnet address"))?;
        listener.dial(address).await
    }

    /// Binds a listener on an automatically allocated localhost port.
    ///
    /// This panics only if the in-memory registry cannot allocate a port.
    #[must_use]
    pub fn new_local_tcp_listener(&self) -> Arc<MemListener> {
        self.listen_inner("127.0.0.1:0")
            .expect("failed to create local memnet listener")
    }

    fn listen_inner(&self, address: &str) -> io::Result<Arc<MemListener>> {
        let parsed = address.parse::<SocketAddr>().ok();
        let mut listeners = self
            .listeners
            .write()
            .expect("network registry lock poisoned");
        let key = match parsed {
            Some(socket_addr) if socket_addr.port() == 0 => {
                self.allocate_port(socket_addr, &listeners)?
            }
            Some(socket_addr) => socket_addr.to_string(),
            None => address.to_owned(),
        };
        if listeners.contains_key(&key) {
            return Err(io::Error::new(
                ErrorKind::AddrInUse,
                "memnet address already in use",
            ));
        }

        let listener = Arc::new(MemListener::listen(&key));
        listener.set_on_close(self.remove_callback(&key, &listener));
        listeners.insert(key, Arc::clone(&listener));
        Ok(listener)
    }

    fn allocate_port(
        &self,
        socket_addr: SocketAddr,
        listeners: &HashMap<String, Arc<MemListener>>,
    ) -> io::Result<String> {
        for _ in 0..(u16::MAX as usize) {
            let port = self.next_port.fetch_add(1, Ordering::Relaxed);
            if port > u16::MAX as usize {
                return Err(io::Error::new(
                    ErrorKind::AddrNotAvailable,
                    "memnet port range exhausted",
                ));
            }
            let key = SocketAddr::new(socket_addr.ip(), port as u16).to_string();
            if !listeners.contains_key(&key) {
                return Ok(key);
            }
        }
        Err(io::Error::new(
            ErrorKind::AddrNotAvailable,
            "memnet port range exhausted",
        ))
    }

    fn remove_callback(
        &self,
        key: &str,
        listener: &Arc<MemListener>,
    ) -> Box<dyn FnOnce() + Send + 'static> {
        let listeners = Arc::downgrade(&self.listeners);
        let key = key.to_owned();
        let listener = Arc::downgrade(listener);
        Box::new(move || remove_listener(listeners, key, listener))
    }
}

fn remove_listener(
    listeners: Weak<RwLock<HashMap<String, Arc<MemListener>>>>,
    key: String,
    listener: Weak<MemListener>,
) {
    let Some(listeners) = listeners.upgrade() else {
        return;
    };
    let mut listeners = listeners.write().expect("network registry lock poisoned");
    if listeners
        .get(&key)
        .is_some_and(|current| Weak::ptr_eq(&Arc::downgrade(current), &listener))
    {
        listeners.remove(&key);
    }
}
