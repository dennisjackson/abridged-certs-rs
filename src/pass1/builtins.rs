/* TODO: Crate Feature // Conditional Compilation */

include!(concat!(env!("OUT_DIR"), "/builtin_tables.rs"));

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut result_256 = [0; 32];
    blake::hash(256, bytes, &mut result_256).expect("Error hashing");
    result_256
}

pub fn cert_to_identifier(cert: &[u8])  -> Option<&'static [u8]> {
    let h = hash(cert);
    HASH_TO_ID.get(&h).copied()
}

pub fn id_to_cert(id: &[u8]) -> Option<&'static [u8]> {
    ID_TO_CERT.get(id).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    /* These tests check for bijectivity */

    #[test]
    fn hashes_entries_agree() {
        for (h, id) in HASH_TO_ID.entries() {
            let cert = id_to_cert(*id).expect("Should be present");
            assert_eq!(hash(&cert), *h);
        }
    }

    #[test]
    fn id_entries_agree() {
        for (id, cert) in ID_TO_CERT.entries() {
            let lookup = cert_to_identifier(*cert).expect("Should be present");
            assert_eq!(*id, lookup);
        }
    }
}
