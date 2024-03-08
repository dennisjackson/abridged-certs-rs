#![no_main]

use libfuzzer_sys::fuzz_target;
use abridged_certs::tls;
use bytes::Bytes;

fuzz_target!(|data: &[u8]| {
    let mut b = Bytes::copy_from_slice(data);
    let cm = abridged_certs::tls::CertificateMessage::read_from_bytes(&mut b.clone());
    if let Ok(cm) = cm {
        let msg_bytes : Vec<u8> = Vec::new();
        let mut cursor = std::io::Cursor::new(msg_bytes);
        cm.write_to_bytes(&mut cursor).expect("No errors");
        let msg_bytes = cursor.into_inner();
        /* Ok to have some trailing data, since could be multiple messages */
        assert_eq!(msg_bytes, b[..msg_bytes.len()]);
    }
});
