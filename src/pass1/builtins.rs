use super::CertIdentifier;
use bytes::Bytes;

include!(concat!(env!("OUT_DIR"), "/builtin_tables.rs"));

pub fn cert_to_identifier(cert: &Bytes) -> Option<CertIdentifier> {
    todo!("Implement")
}

pub fn id_to_cert(id: &CertIdentifier) -> Option<Bytes> {
    todo!("Implement")
}
