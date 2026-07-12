#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rustscale_netcheck::parse_response(data);
    let _ = rustscale_netcheck::parse_binding_request(data);
});
