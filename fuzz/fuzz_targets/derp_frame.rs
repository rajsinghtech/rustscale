#![no_main]
use libfuzzer_sys::fuzz_target;
use rustscale_derp::{decode_frame_header, read_frame, MAX_PACKET_SIZE};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 5 {
        let mut hdr = [0u8; 5];
        hdr.copy_from_slice(&data[..5]);
        let _ = decode_frame_header(&hdr);
    }
    let mut cursor = Cursor::new(data);
    let mut buf = Vec::new();
    let _ = read_frame(&mut cursor, MAX_PACKET_SIZE as u32, &mut buf);
});
