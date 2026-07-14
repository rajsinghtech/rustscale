use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{BuildHasher, Hash};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rustscale_ipn::{AppConnectorPrefs, MaskedPrefs, Prefs, State};
use rustscale_key::{DiscoPublic, MachinePublic, NodePublic};
use rustscale_tailcfg::{
    CapGrant, ClientVersion, DNSConfig, DNSRecord, EndpointType, FilterRule, Hostinfo, Location,
    MapResponse, NetInfo, NetPortRange, OptBool, PeerChange, PortRange, RawMessage, Resolver,
    Service, TPMInfo,
};
use serde::Serialize;

use crate::{DeepHash, Hasher, Sum};

macro_rules! impl_unsigned {
    ($($type:ty => $method:ident),+ $(,)?) => {
        $(impl DeepHash for $type {
            fn deep_hash(&self, hasher: &mut Hasher) { hasher.$method(*self); }
        })+
    };
}
impl_unsigned!(u8 => hash_uint8, u16 => hash_uint16, u32 => hash_uint32, u64 => hash_uint64);

macro_rules! impl_signed {
    ($($type:ty => $unsigned:ty => $method:ident),+ $(,)?) => {
        $(impl DeepHash for $type {
            fn deep_hash(&self, hasher: &mut Hasher) { hasher.$method(*self as $unsigned); }
        })+
    };
}
impl_signed!(i8 => u8 => hash_uint8, i16 => u16 => hash_uint16, i32 => u32 => hash_uint32, i64 => u64 => hash_uint64);

macro_rules! impl_bytes {
    ($($type:ty),+ $(,)?) => { $(impl DeepHash for $type {
        fn deep_hash(&self, hasher: &mut Hasher) { hasher.hash_bytes(&self.to_le_bytes()); }
    })+ };
}
impl_bytes!(u128, i128, usize, isize, f32, f64);

impl DeepHash for bool {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint8(u8::from(*self));
    }
}
impl DeepHash for char {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint32(u32::from(*self));
    }
}
impl DeepHash for str {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint64(self.len() as u64);
        hasher.hash_string(self);
    }
}
impl DeepHash for String {
    fn deep_hash(&self, hasher: &mut Hasher) {
        self.as_str().deep_hash(hasher);
    }
}
impl<T: DeepHash + ?Sized> DeepHash for &T {
    fn deep_hash(&self, hasher: &mut Hasher) {
        (*self).deep_hash(hasher);
    }
}
impl<T: DeepHash> DeepHash for Vec<T> {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint8(1);
        hasher.hash_uint64(self.len() as u64);
        for value in self {
            value.deep_hash(hasher);
        }
    }
}
impl<T: DeepHash> DeepHash for [T] {
    fn deep_hash(&self, hasher: &mut Hasher) {
        for value in self {
            value.deep_hash(hasher);
        }
    }
}
impl<T: DeepHash, const N: usize> DeepHash for [T; N] {
    fn deep_hash(&self, hasher: &mut Hasher) {
        self.as_slice().deep_hash(hasher);
    }
}
impl<T: DeepHash> DeepHash for Option<T> {
    fn deep_hash(&self, hasher: &mut Hasher) {
        match self {
            Some(value) => {
                hasher.hash_uint8(1);
                value.deep_hash(hasher);
            }
            None => hasher.hash_uint8(0),
        }
    }
}
impl<T: DeepHash> DeepHash for Box<T> {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint8(1);
        (**self).deep_hash(hasher);
    }
}
impl<T: DeepHash + ?Sized> DeepHash for Arc<T> {
    fn deep_hash(&self, hasher: &mut Hasher) {
        (**self).deep_hash(hasher);
    }
}
impl<K: DeepHash + Hash + Eq, V: DeepHash, S: BuildHasher> DeepHash for HashMap<K, V, S> {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint8(1);
        hasher.hash_uint64(self.len() as u64);
        let mut entries = Sum([0; 32]);
        for (key, value) in self {
            let mut entry_hasher = Hasher::new();
            key.deep_hash(&mut entry_hasher);
            value.deep_hash(&mut entry_hasher);
            entries.xor(&entry_hasher.finalize());
        }
        hasher.hash_sum(&entries);
    }
}
impl<K: DeepHash + Ord, V: DeepHash> DeepHash for BTreeMap<K, V> {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint64(self.len() as u64);
        for (key, value) in self {
            key.deep_hash(hasher);
            value.deep_hash(hasher);
        }
    }
}
impl<T: DeepHash + Ord> DeepHash for BTreeSet<T> {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint64(self.len() as u64);
        for value in self {
            value.deep_hash(hasher);
        }
    }
}
impl DeepHash for IpAddr {
    fn deep_hash(&self, hasher: &mut Hasher) {
        match self {
            Self::V4(value) => value.deep_hash(hasher),
            Self::V6(value) => value.deep_hash(hasher),
        }
    }
}
impl DeepHash for Ipv4Addr {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint8(4);
        hasher.hash_bytes(&self.octets());
    }
}
impl DeepHash for Ipv6Addr {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint8(16);
        hasher.hash_bytes(&self.octets());
    }
}
impl DeepHash for DateTime<Utc> {
    fn deep_hash(&self, hasher: &mut Hasher) {
        hasher.hash_uint64(self.timestamp() as u64);
        hasher.hash_uint32(self.timestamp_subsec_nanos());
    }
}
impl DeepHash for NodePublic {
    fn deep_hash(&self, h: &mut Hasher) {
        h.hash_bytes(&self.raw32());
    }
}
impl DeepHash for MachinePublic {
    fn deep_hash(&self, h: &mut Hasher) {
        h.hash_bytes(&self.raw32());
    }
}
impl DeepHash for DiscoPublic {
    fn deep_hash(&self, h: &mut Hasher) {
        h.hash_bytes(&self.raw32());
    }
}
impl DeepHash for RawMessage {
    fn deep_hash(&self, h: &mut Hasher) {
        self.0.deep_hash(h);
    }
}
impl DeepHash for OptBool {
    fn deep_hash(&self, h: &mut Hasher) {
        self.get().deep_hash(h);
    }
}

impl DeepHash for PortRange {
    fn deep_hash(&self, h: &mut Hasher) {
        self.First.deep_hash(h);
        self.Last.deep_hash(h);
    }
}
impl DeepHash for NetPortRange {
    fn deep_hash(&self, h: &mut Hasher) {
        self.IP.deep_hash(h);
        self.Bits.deep_hash(h);
        self.Ports.deep_hash(h);
    }
}
impl DeepHash for CapGrant {
    fn deep_hash(&self, h: &mut Hasher) {
        self.Dsts.deep_hash(h);
        self.Caps.deep_hash(h);
        self.CapMap.deep_hash(h);
    }
}
impl DeepHash for FilterRule {
    fn deep_hash(&self, h: &mut Hasher) {
        self.SrcIPs.deep_hash(h);
        self.SrcBits.deep_hash(h);
        self.DstPorts.deep_hash(h);
        self.IPProto.deep_hash(h);
        self.CapGrant.deep_hash(h);
    }
}
impl DeepHash for Resolver {
    fn deep_hash(&self, h: &mut Hasher) {
        self.Addr.deep_hash(h);
    }
}
impl DeepHash for DNSRecord {
    fn deep_hash(&self, h: &mut Hasher) {
        self.Name.deep_hash(h);
        self.Type.deep_hash(h);
        self.Value.deep_hash(h);
    }
}
impl DeepHash for DNSConfig {
    fn deep_hash(&self, h: &mut Hasher) {
        self.Resolvers.deep_hash(h);
        self.Routes.deep_hash(h);
        self.FallbackResolvers.deep_hash(h);
        self.Domains.deep_hash(h);
        self.Proxied.deep_hash(h);
        self.CertDomains.deep_hash(h);
        self.ExtraRecords.deep_hash(h);
        self.Nameservers.deep_hash(h);
    }
}
impl DeepHash for Service {
    fn deep_hash(&self, h: &mut Hasher) {
        self.Proto.deep_hash(h);
        self.Port.deep_hash(h);
        self.Description.deep_hash(h);
    }
}
impl DeepHash for NetInfo {
    fn deep_hash(&self, h: &mut Hasher) {
        self.MappingVariesByDestIP.deep_hash(h);
        self.WorkingIPv6.deep_hash(h);
        self.OSHasIPv6.deep_hash(h);
        self.WorkingUDP.deep_hash(h);
        self.WorkingICMPv4.deep_hash(h);
        self.HavePortMap.deep_hash(h);
        self.UPnP.deep_hash(h);
        self.PMP.deep_hash(h);
        self.PCP.deep_hash(h);
        self.PreferredDERP.deep_hash(h);
        self.LinkType.deep_hash(h);
        self.DERPLatency.deep_hash(h);
        self.FirewallMode.deep_hash(h);
    }
}
impl DeepHash for Location {
    fn deep_hash(&self, h: &mut Hasher) {
        self.Country.deep_hash(h);
        self.CountryCode.deep_hash(h);
    }
}
impl DeepHash for TPMInfo {
    fn deep_hash(&self, h: &mut Hasher) {
        self.Manufacturer.deep_hash(h);
        self.Vendor.deep_hash(h);
        self.Model.deep_hash(h);
        self.FirmwareVersion.deep_hash(h);
        self.SpecRevision.deep_hash(h);
        self.FamilyIndicator.deep_hash(h);
    }
}
impl DeepHash for Hostinfo {
    fn deep_hash(&self, h: &mut Hasher) {
        self.IPNVersion.deep_hash(h);
        self.FrontendLogID.deep_hash(h);
        self.BackendLogID.deep_hash(h);
        self.OS.deep_hash(h);
        self.OSVersion.deep_hash(h);
        self.Container.deep_hash(h);
        self.Env.deep_hash(h);
        self.Distro.deep_hash(h);
        self.DistroVersion.deep_hash(h);
        self.DistroCodeName.deep_hash(h);
        self.App.deep_hash(h);
        self.Desktop.deep_hash(h);
        self.Package.deep_hash(h);
        self.DeviceModel.deep_hash(h);
        self.PushDeviceToken.deep_hash(h);
        self.Hostname.deep_hash(h);
        self.ShieldsUp.deep_hash(h);
        self.ShareeNode.deep_hash(h);
        self.NoLogsNoSupport.deep_hash(h);
        self.WireIngress.deep_hash(h);
        self.IngressEnabled.deep_hash(h);
        self.AllowsUpdate.deep_hash(h);
        self.Machine.deep_hash(h);
        self.GoArch.deep_hash(h);
        self.GoArchVar.deep_hash(h);
        self.GoVersion.deep_hash(h);
        self.RoutableIPs.deep_hash(h);
        self.RequestTags.deep_hash(h);
        self.WoLMACs.deep_hash(h);
        self.Services.deep_hash(h);
        self.NetInfo.deep_hash(h);
        self.SSH_HostKeys.deep_hash(h);
        self.Cloud.deep_hash(h);
        self.Userspace.deep_hash(h);
        self.UserspaceRouter.deep_hash(h);
        self.AppConnector.deep_hash(h);
        self.ServicesHash.deep_hash(h);
        self.PeerRelay.deep_hash(h);
        self.ExitNodeID.deep_hash(h);
        self.Location.deep_hash(h);
        self.TPM.deep_hash(h);
        self.StateEncrypted.deep_hash(h);
    }
}
impl DeepHash for rustscale_tailcfg::Node {
    fn deep_hash(&self, h: &mut Hasher) {
        self.ID.deep_hash(h);
        self.StableID.deep_hash(h);
        self.Name.deep_hash(h);
        self.User.deep_hash(h);
        self.Key.deep_hash(h);
        self.KeyExpiry.deep_hash(h);
        self.KeySignature.deep_hash(h);
        self.Machine.deep_hash(h);
        self.DiscoKey.deep_hash(h);
        self.Addresses.deep_hash(h);
        self.AllowedIPs.deep_hash(h);
        self.PrimaryRoutes.deep_hash(h);
        self.Endpoints.deep_hash(h);
        self.HomeDERP.deep_hash(h);
        self.Hostinfo.deep_hash(h);
        self.Created.deep_hash(h);
        self.Cap.deep_hash(h);
        self.Tags.deep_hash(h);
        self.LastSeen.deep_hash(h);
        self.Online.deep_hash(h);
        self.Capabilities.deep_hash(h);
        self.CapMap.deep_hash(h);
        self.UnsignedPeerAPIOnly.deep_hash(h);
        self.Expired.deep_hash(h);
        self.IsWireGuardOnly.deep_hash(h);
        self.IsJailed.deep_hash(h);
    }
}
impl DeepHash for PeerChange {
    fn deep_hash(&self, h: &mut Hasher) {
        self.NodeID.deep_hash(h);
        self.DERPRegion.deep_hash(h);
        self.Cap.deep_hash(h);
        self.CapMap.deep_hash(h);
        self.Endpoints.deep_hash(h);
        self.Key.deep_hash(h);
        self.KeySignature.deep_hash(h);
        self.DiscoKey.deep_hash(h);
        self.Online.deep_hash(h);
        self.LastSeen.deep_hash(h);
        self.KeyExpiry.deep_hash(h);
    }
}
impl DeepHash for AppConnectorPrefs {
    fn deep_hash(&self, h: &mut Hasher) {
        self.Advertise.deep_hash(h);
    }
}
impl DeepHash for Prefs {
    fn deep_hash(&self, h: &mut Hasher) {
        self.ControlURL.deep_hash(h);
        self.WantRunning.deep_hash(h);
        self.LoggedOut.deep_hash(h);
        self.RouteAll.deep_hash(h);
        self.ExitNodeID.deep_hash(h);
        self.ExitNodeIP.deep_hash(h);
        self.CorpDNS.deep_hash(h);
        self.ShieldsUp.deep_hash(h);
        self.Hostname.deep_hash(h);
        self.AdvertiseRoutes.deep_hash(h);
        self.AdvertiseTags.deep_hash(h);
        self.OperatorUser.deep_hash(h);
        self.Ephemeral.deep_hash(h);
        self.AcceptRoutes.deep_hash(h);
        self.AdvertiseExitNode.deep_hash(h);
        self.ExitNodeAllowLANAccess.deep_hash(h);
        self.AutoUpdate.deep_hash(h);
        self.NetfilterMode.deep_hash(h);
        self.NoSNAT.deep_hash(h);
        self.PostureChecking.deep_hash(h);
        self.AppConnector.deep_hash(h);
        self.RunWebClient.deep_hash(h);
        self.RunSSH.deep_hash(h);
        self.NoStatefulFiltering.deep_hash(h);
        self.NoLogsNoSupport.deep_hash(h);
    }
}
impl DeepHash for MaskedPrefs {
    fn deep_hash(&self, h: &mut Hasher) {
        self.Prefs.deep_hash(h);
        self.ControlURLSet.deep_hash(h);
        self.WantRunningSet.deep_hash(h);
        self.LoggedOutSet.deep_hash(h);
        self.RouteAllSet.deep_hash(h);
        self.ExitNodeIDSet.deep_hash(h);
        self.ExitNodeIPSet.deep_hash(h);
        self.CorpDNSSet.deep_hash(h);
        self.ShieldsUpSet.deep_hash(h);
        self.HostnameSet.deep_hash(h);
        self.AdvertiseRoutesSet.deep_hash(h);
        self.AdvertiseTagsSet.deep_hash(h);
        self.OperatorUserSet.deep_hash(h);
        self.EphemeralSet.deep_hash(h);
        self.AcceptRoutesSet.deep_hash(h);
        self.AdvertiseExitNodeSet.deep_hash(h);
        self.ExitNodeAllowLANAccessSet.deep_hash(h);
        self.AutoUpdateSet.deep_hash(h);
        self.NetfilterModeSet.deep_hash(h);
        self.NoSNATSet.deep_hash(h);
        self.PostureCheckingSet.deep_hash(h);
        self.AppConnectorSet.deep_hash(h);
        self.RunWebClientSet.deep_hash(h);
        self.RunSSHSet.deep_hash(h);
        self.NoStatefulFilteringSet.deep_hash(h);
        self.NoLogsNoSupportSet.deep_hash(h);
    }
}
impl DeepHash for State {
    fn deep_hash(&self, h: &mut Hasher) {
        h.hash_uint8(*self as u8);
    }
}
impl DeepHash for ClientVersion {
    fn deep_hash(&self, h: &mut Hasher) {
        self.RunningLatest.deep_hash(h);
        self.LatestVersion.deep_hash(h);
        self.UrgentSecurityUpdate.deep_hash(h);
        self.Notify.deep_hash(h);
        self.NotifyURL.deep_hash(h);
        self.NotifyText.deep_hash(h);
    }
}
impl DeepHash for EndpointType {
    fn deep_hash(&self, h: &mut Hasher) {
        self.0.deep_hash(h);
    }
}
impl DeepHash for MapResponse {
    fn deep_hash(&self, h: &mut Hasher) {
        self.MapSessionHandle.deep_hash(h);
        self.Seq.deep_hash(h);
        self.KeepAlive.deep_hash(h);
        self.Node.deep_hash(h);
        hash_json(h, &self.DERPMap);
        self.Peers.deep_hash(h);
        self.PeersChanged.deep_hash(h);
        self.PeersRemoved.deep_hash(h);
        self.Domain.deep_hash(h);
        self.DNSConfig.deep_hash(h);
        hash_json(h, &self.UserProfiles);
        self.PacketFilter.deep_hash(h);
        self.PacketFilters.deep_hash(h);
        self.NodeKeyExpired.deep_hash(h);
        self.ControlTime.deep_hash(h);
        self.CollectServices.deep_hash(h);
        hash_json(h, &self.SSHPolicy);
        self.PeersChangedPatch.deep_hash(h);
        self.NetInfo.deep_hash(h);
        hash_json(h, &self.ClientVersion);
        self.SuggestedExitNode.deep_hash(h);
    }
}

fn hash_json<T: Serialize>(hasher: &mut Hasher, value: &T) {
    let bytes = serde_json::to_vec(value).expect("rustscale wire type must serialize to JSON");
    hasher.hash_uint64(bytes.len() as u64);
    hasher.hash_bytes(&bytes);
}
