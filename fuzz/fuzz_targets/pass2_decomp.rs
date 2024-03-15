#![no_main]

use abridged_certs::pass2;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
        let c = pass2::Decompressor::new_from_builtin();
        if let Ok(out) = c
            .decompress_to_bytes(&data,16000)  {
                assert!(out.len() < 16000);
            }
});
