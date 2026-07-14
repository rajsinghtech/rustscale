/// Collect hardware addresses for all non-loopback network interfaces.
pub fn get_hardware_addrs() -> Vec<String> {
    let addrs = rustscale_netmon::get_interface_list()
        .into_iter()
        .filter(|iface| !iface.meta.is_loopback)
        .filter_map(|iface| iface.meta.hw_addr)
        .map(format_mac)
        .collect();
    dedup_hardware_addrs(addrs)
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn dedup_hardware_addrs(mut addrs: Vec<String>) -> Vec<String> {
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}

#[cfg(test)]
mod tests {
    use super::dedup_hardware_addrs;

    #[test]
    fn hwaddr_empty() {
        assert!(dedup_hardware_addrs(Vec::new()).is_empty());
    }
}
