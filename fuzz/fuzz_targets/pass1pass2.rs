#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let c = abridged_certs::Decompressor::new_from_builtin();
    if let Ok(out) = c
        .decompress_to_bytes(&data,16000)  {
            assert!(out.len() < 16000);
        }
});
