use super::CertIdentifier;
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
    HASH_TO_ID.get(&h).map(|x| Bytes::from_static(x))
}

pub fn id_to_cert(id: &CertIdentifier) -> Option<Bytes> {
    ID_TO_CERT.get(id).map(|x| Bytes::from_static(x))
}

#[cfg(test)]
mod tests {
    use super::*;

    /* These tests check for bijectivity */

    #[test]
    fn hashes_entries_agree() {
        for (h, id) in HASH_TO_ID.entries() {
            let cert = id_to_cert(&Bytes::from(*id)).expect("Should be present");
            assert_eq!(hash(&cert), *h);
        }
    }

    #[test]
    fn id_entries_agree() {
        for (id, cert) in ID_TO_CERT.entries() {
            let lookup = cert_to_identifier(&Bytes::from(*cert)).expect("Should be present");
            assert_eq!(*id, lookup);
        }
    }
}
