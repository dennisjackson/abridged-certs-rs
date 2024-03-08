use super::CertIdentifier;
use blake;
use bytes::Bytes;

/* TODO: Crate Feature // Conditional Compilation */

include!(concat!(env!("OUT_DIR"), "/builtin_tables.rs"));

/* TODO: Fix this crime */
fn hash(bytes: &[u8]) -> Vec<u8> {
    let mut result_256 = [0; 32];
    blake::hash(256, bytes, &mut result_256).expect("Error hashing");
    result_256.to_vec()
}

pub fn cert_to_identifier(cert: &Bytes) -> Option<CertIdentifier> {
    let h = hash(cert);
    match HASH_TO_ID.get(&h) {
        Some(x) => Some(Bytes::from_static(*x)),
        None => None,
    }
}

pub fn id_to_cert(id: &CertIdentifier) -> Option<Bytes> {
    match ID_TO_CERT.get(id) {
        Some(x) => Some(Bytes::from_static(*x)),
        None => None,
    }
}
