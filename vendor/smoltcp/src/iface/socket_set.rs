use core::fmt;
use managed::ManagedSlice;

#[cfg(all(feature = "alloc", feature = "socket-tcp"))]
use alloc::collections::BTreeMap;

use super::socket_meta::Meta;
#[cfg(all(feature = "alloc", feature = "socket-tcp"))]
use crate::socket::tcp;
use crate::socket::{AnySocket, Socket};
#[cfg(all(feature = "alloc", feature = "socket-tcp"))]
use crate::wire::IpEndpoint;

#[cfg(all(feature = "alloc", feature = "socket-tcp"))]
type TcpFlowKey = (IpEndpoint, IpEndpoint);

/// Opaque struct with space for storing one socket.
///
/// This is public so you can use it to allocate space for storing
/// sockets when creating an Interface.
#[derive(Debug, Default)]
pub struct SocketStorage<'a> {
    inner: Option<Item<'a>>,
}

impl<'a> SocketStorage<'a> {
    pub const EMPTY: Self = Self { inner: None };
}

/// An item of a socket set.
#[derive(Debug)]
pub(crate) struct Item<'a> {
    pub(crate) meta: Meta,
    pub(crate) socket: Socket<'a>,
}

/// A handle, identifying a socket in an Interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SocketHandle(usize);

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of sockets.
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.  If you're using
/// owned buffers for your sockets (passed in as `Vec`s) you can use
/// `SocketSet<'static>`.
#[derive(Debug)]
pub struct SocketSet<'a> {
    sockets: ManagedSlice<'a, SocketStorage<'a>>,
    #[cfg(all(feature = "alloc", feature = "socket-tcp"))]
    tcp_flows: BTreeMap<TcpFlowKey, SocketHandle>,
    #[cfg(all(feature = "alloc", feature = "socket-tcp"))]
    tcp_flow_keys: BTreeMap<SocketHandle, TcpFlowKey>,
}

impl<'a> SocketSet<'a> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> SocketSet<'a>
    where
        SocketsT: Into<ManagedSlice<'a, SocketStorage<'a>>>,
    {
        let sockets = sockets.into();
        SocketSet {
            sockets,
            #[cfg(all(feature = "alloc", feature = "socket-tcp"))]
            tcp_flows: BTreeMap::new(),
            #[cfg(all(feature = "alloc", feature = "socket-tcp"))]
            tcp_flow_keys: BTreeMap::new(),
        }
    }

    /// Add a socket to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add<T: AnySocket<'a>>(&mut self, socket: T) -> SocketHandle {
        fn put<'a>(index: usize, slot: &mut SocketStorage<'a>, socket: Socket<'a>) -> SocketHandle {
            net_trace!("[{}]: adding", index);
            let handle = SocketHandle(index);
            let mut meta = Meta::default();
            meta.handle = handle;
            *slot = SocketStorage {
                inner: Some(Item { meta, socket }),
            };
            handle
        }

        let socket = socket.upcast();

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.inner.is_none() {
                return put(index, slot, socket);
            }
        }

        match &mut self.sockets {
            ManagedSlice::Borrowed(_) => panic!("adding a socket to a full SocketSet"),
            #[cfg(feature = "alloc")]
            ManagedSlice::Owned(sockets) => {
                sockets.push(SocketStorage { inner: None });
                let index = sockets.len() - 1;
                put(index, &mut sockets[index], socket)
            }
        }
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'a>>(&self, handle: SocketHandle) -> &T {
        match self.sockets[handle.0].inner.as_ref() {
            Some(item) => {
                T::downcast(&item.socket).expect("handle refers to a socket of a wrong type")
            }
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get a mutable socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_mut<T: AnySocket<'a>>(&mut self, handle: SocketHandle) -> &mut T {
        match self.sockets[handle.0].inner.as_mut() {
            Some(item) => T::downcast_mut(&mut item.socket)
                .expect("handle refers to a socket of a wrong type"),
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    pub(crate) fn get_mut_checked<T: AnySocket<'a>>(
        &mut self,
        handle: SocketHandle,
    ) -> Option<&mut T> {
        self.sockets
            .get_mut(handle.0)?
            .inner
            .as_mut()
            .and_then(|item| T::downcast_mut(&mut item.socket))
    }

    /// Add an established TCP socket to the exact inbound flow index.
    ///
    /// Returns false when `handle` is not a connected TCP socket with both
    /// endpoints populated. Callers register established sockets; listener
    /// and handshake packets deliberately keep using the complete scan.
    #[cfg(all(feature = "alloc", feature = "socket-tcp"))]
    pub fn register_tcp_flow(&mut self, handle: SocketHandle) -> bool {
        let Some(socket) = self.get_mut_checked::<tcp::Socket<'a>>(handle) else {
            return false;
        };
        let (Some(local), Some(remote)) = (socket.local_endpoint(), socket.remote_endpoint())
        else {
            return false;
        };
        let key = (remote, local);
        if let Some(old_key) = self.tcp_flow_keys.insert(handle, key) {
            self.tcp_flows.remove(&old_key);
        }
        if let Some(old_handle) = self.tcp_flows.insert(key, handle) {
            self.tcp_flow_keys.remove(&old_handle);
        }
        true
    }

    #[cfg(all(feature = "alloc", feature = "socket-tcp"))]
    pub(crate) fn tcp_flow_handle(
        &self,
        remote: IpEndpoint,
        local: IpEndpoint,
    ) -> Option<SocketHandle> {
        self.tcp_flows.get(&(remote, local)).copied()
    }

    #[cfg(all(feature = "alloc", feature = "socket-tcp"))]
    pub(crate) fn forget_tcp_flow(&mut self, remote: IpEndpoint, local: IpEndpoint) {
        if let Some(handle) = self.tcp_flows.remove(&(remote, local)) {
            self.tcp_flow_keys.remove(&handle);
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'a> {
        net_trace!("[{}]: removing", handle.0);
        #[cfg(all(feature = "alloc", feature = "socket-tcp"))]
        if let Some(key) = self.tcp_flow_keys.remove(&handle) {
            self.tcp_flows.remove(&key);
        }
        match self.sockets[handle.0].inner.take() {
            Some(item) => item.socket,
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get an iterator to the inner sockets.
    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &Socket<'a>)> {
        self.items().map(|i| (i.meta.handle, &i.socket))
    }

    /// Get a mutable iterator to the inner sockets.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket<'a>)> {
        self.items_mut().map(|i| (i.meta.handle, &mut i.socket))
    }

    /// Iterate every socket in this set.
    pub(crate) fn items(&self) -> impl Iterator<Item = &Item<'a>> + '_ {
        self.sockets.iter().filter_map(|x| x.inner.as_ref())
    }

    /// Iterate every socket in this set.
    pub(crate) fn items_mut(&mut self) -> impl Iterator<Item = &mut Item<'a>> + '_ {
        self.sockets.iter_mut().filter_map(|x| x.inner.as_mut())
    }

    /// Number of storage slots, including vacant slots.
    pub(crate) fn storage_len(&self) -> usize {
        self.sockets.len()
    }

    /// Iterate every socket cyclically, beginning at `start`.
    ///
    /// Storage indices remain stable so [`SocketHandle`] values do not change.
    pub(crate) fn items_mut_from(
        &mut self,
        start: usize,
    ) -> impl Iterator<Item = (usize, &mut Item<'a>)> + '_ {
        let split = start.min(self.sockets.len());
        let (before, after) = self.sockets.split_at_mut(split);
        after
            .iter_mut()
            .enumerate()
            .map(move |(offset, slot)| (split + offset, slot))
            .chain(before.iter_mut().enumerate())
            .filter_map(|(index, slot)| slot.inner.as_mut().map(|item| (index, item)))
    }
}

#[cfg(all(
    test,
    feature = "alloc",
    feature = "medium-ip",
    feature = "proto-ipv4",
    feature = "socket-tcp"
))]
mod tests {
    use super::*;
    use crate::phy::Medium;
    use crate::socket::tcp::SocketBuffer;
    use crate::wire::IpAddress;

    #[test]
    fn registered_tcp_flow_is_exact_and_removed_with_socket() {
        let (mut iface, mut sockets, _) = crate::tests::setup(Medium::Ip);
        let remote = IpEndpoint::new(IpAddress::v4(192, 168, 1, 2), 443);
        let local = IpEndpoint::new(IpAddress::v4(192, 168, 1, 1), 49152);
        let mut socket = tcp::Socket::new(
            SocketBuffer::new(alloc::vec![0; 64]),
            SocketBuffer::new(alloc::vec![0; 64]),
        );
        socket.connect(iface.context(), remote, local).unwrap();
        let handle = sockets.add(socket);

        assert!(sockets.register_tcp_flow(handle));
        assert_eq!(sockets.tcp_flow_handle(remote, local), Some(handle));
        assert_eq!(sockets.tcp_flow_handle(local, remote), None);

        let _ = sockets.remove(handle);
        assert_eq!(sockets.tcp_flow_handle(remote, local), None);
    }
}
