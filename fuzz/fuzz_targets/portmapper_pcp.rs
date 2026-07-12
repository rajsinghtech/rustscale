#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rustscale_portmapper::_fuzz::parse_pcp_header(data);
    let _ = rustscale_portmapper::_fuzz::parse_pcp_map_response(data);
});
