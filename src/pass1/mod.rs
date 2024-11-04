use super::tls::{CertificateEntry, CertificateMessage};
use bytes::{BufMut, Bytes};
use std::io::Write;

mod builtins;

pub type IdFunc = fn(&[u8]) -> Option<&'static [u8]>;
pub type CertFunc = fn(&[u8]) -> Option<&'static [u8]>;

#[derive(Debug)]
pub struct Compressor {
    lookup: IdFunc,
}

impl Compressor {
    pub fn new(lookup: IdFunc) -> Self {
        Compressor { lookup }
    }

    pub fn new_builtin() -> Self {
        Compressor {
            lookup: builtins::cert_to_identifier,
        }
    }

    fn map_or_preserve_cert_entry(&self, mut entry: CertificateEntry) -> CertificateEntry {
        let cert = &entry.data;
        /* Debug builds validate that the user supplied function is correct */
        debug_assert_eq!(
            (self.lookup)(cert),
            self::builtins::cert_to_identifier(cert)
        );
        entry.data = (self.lookup)(cert).map_or(entry.data, Bytes::from_static);
        entry
    }

    pub fn compress_to_bytes(
        &self,
        cert_msg: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let output = Vec::with_capacity(cert_msg.len());
        let mut writer = output.writer();
        self.compress(cert_msg, &mut writer)?;
        Ok(writer.into_inner())
    }

    pub fn compress(
        &self,
        cert_msg: &[u8],
        writer: &mut impl Write,
    ) -> Result<(), Box<dyn std::error::Error>> {
        /* TODO: Why do we need ownership here? It would be nice just to reference the slice */
        let mut cert_msg = Bytes::copy_from_slice(cert_msg);
        let mut cert_msg = CertificateMessage::read_from_bytes(&mut cert_msg)?;
        cert_msg.certificate_entries = cert_msg
            .certificate_entries
            .into_iter()
            .map(|x| self.map_or_preserve_cert_entry(x))
            .collect();
        cert_msg.write_to_bytes(writer)?;
        Ok(())
    }
}



#[derive(Debug)]
pub struct Decompressor {
    lookup: CertFunc,
}

impl Decompressor {
    pub fn new(lookup: CertFunc) -> Self {
        Decompressor { lookup }
    }

    pub fn new_builtin() -> Self {
        Decompressor {
            lookup: builtins::id_to_cert,
        }
    }

    fn map_identifier(&self, mut entry: CertificateEntry) -> CertificateEntry {
        let id_or_cert = &entry.data;
        /* Debug builds validate that the user supplied function is correct */
        debug_assert_eq!(
            (self.lookup)(id_or_cert),
            self::builtins::id_to_cert(id_or_cert)
        );
        entry.data = (self.lookup)(id_or_cert).map_or(entry.data, Bytes::from_static);
        entry
    }

    pub fn decompress_to_bytes(
        &self,
        compressed_msg: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let output = Vec::with_capacity(compressed_msg.len());
        let mut writer = output.writer();
        self.decompress(compressed_msg, &mut writer)?;
        Ok(writer.into_inner())
    }

    /* TODO: This needs to support a maximum size */
    pub fn decompress(
        &self,
        compressed_msg: &[u8],
        writer: &mut impl Write,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut compressed_msg = Bytes::copy_from_slice(compressed_msg);
        let mut cert_msg = CertificateMessage::read_from_bytes(&mut compressed_msg)?;
        cert_msg.certificate_entries = cert_msg
            .certificate_entries
            .into_iter()
            .map(|x| self.map_identifier(x))
            .collect();
        cert_msg.write_to_bytes(writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERTMSG: &str = "
        0000032a0003253082032130820209a0030201020208155a92adc2048f90300d06092a86
        4886f70d01010b05003022310b300906035504061302555331133011060355040a130a4578616d70
        6c65204341301e170d3138313030353031333831375a170d3139313030353031333831375a302b31
        0b3009060355040613025553311c301a060355040313136578616d706c652e756c666865696d2e6e
        657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c4803606ba
        e7476b089404eca7b691043ff792bc19eefb7d74d7a80d001e7b4b3a4ae60fe8c071fc73e7024c0d
        bcf4bdd11d396bba70464a13e94af83df3e10959547bc955fb412da3765211e1f3dc776caa53376e
        ca3aecbec3aab73b31d56cb6529c8098bcc9e02818e20bf7f8a03afd1704509ece79bd9f39f1ea69
        ec47972e830fb5ca95de95a1e60422d5eebe527954a1e7bf8a86f6466d0d9f16951a4cf7a0469259
        5c1352f2549e5afb4ebfd77a37950144e4c026874c653e407d7d23074401f484ffd08f7a1fa05210
        d1f4f0d5ce79702932e2cabe701fdfad6b4bb71101f44bad666a11130fe2ee829e4d029dc91cdd67
        16dbb9061886edc1ba94210203010001a3523050300e0603551d0f0101ff0404030205a0301d0603
        551d250416301406082b0601050507030206082b06010505070301301f0603551d23041830168014
        894fde5bcc69e252cf3ea300dfb197b81de1c146300d06092a864886f70d01010b05000382010100
        591645a69a2e3779e4f6dd271aba1c0bfd6cd75599b5e7c36e533eff3659084324c9e7a504079d39
        e0d42987ffe3ebdd09c1cf1d914455870b571dd19bdf1d24f8bb9a11fe80fd592ba0398cde11e265
        1e618ce598fa96e5372eef3d248afde17463ebbfabb8e4d1ab502a54ec0064e92f7819660d3f27cf
        209e667fce5ae2e4ac99c7c93818f8b2510722dfed97f32e3e9349d4c66c9ea6396d744462a06b42
        c6d5ba688eac3a017bddfc8e2cfcad27cb69d3ccdca280414465d3ae348ce0f34ab2fb9c61837131
        2b191041641c237f11a5d65c844f0404849938712b959ed685bc5c5dd645ed19909473402926dcb4
        0e3469a15941e8e2cca84bb6084636a00000";

    #[test]
    fn compressor_happy() {
        /* Borrowed from https://tls13.xargs.org/#server-certificate */
        let mut cert_hex: String = String::from(CERTMSG);
        cert_hex.retain(|x| !x.is_whitespace());
        let cert_bytes = hex::decode(cert_hex).unwrap();
        let c = Compressor::new_builtin();
        let out = c
            .compress_to_bytes(&cert_bytes)
            .expect("Compression succeeds");
        println!("Compressed to {} from {}", out.len(), cert_bytes.len());
    }

    #[test]
    fn decompressor_happy() {
        /* Borrowed from https://tls13.xargs.org/#server-certificate */
        let mut cert_hex: String = String::from(CERTMSG);
        cert_hex.retain(|x| !x.is_whitespace());
        let cert_bytes = hex::decode(cert_hex).unwrap();
        let c = Decompressor::new_builtin();
        let out = c
            .decompress_to_bytes(&cert_bytes)
            .expect("Compression succeeds");
        println!("Decompressed from {} from {}", out.len(), cert_bytes.len());
    }

    #[test]
    fn round_trip_happy() {
        let mut cert_hex: String = String::from(CERTMSG);
        cert_hex.retain(|x| !x.is_whitespace());
        let cert_bytes = hex::decode(cert_hex).unwrap();
        let c = Compressor::new_builtin();
        let out = c
            .compress_to_bytes(&cert_bytes)
            .expect("Compression succeeds");
        let c = Decompressor::new_builtin();
        let round_trip = c.decompress_to_bytes(&out).expect("Compression succeeds");
        assert_eq!(cert_bytes, round_trip);
    }
}

#[cfg(test)]
#[cfg(all(feature ="nightly-features"))]
mod datatests {

    #[datatest::files("data/certificate_messages", {
      input in r"^(.*)"
    })]
    fn sample_test(input: &[u8]) {
        let cert_bytes = bytes::Bytes::copy_from_slice(input);
        let c = crate::pass1::Compressor::new_builtin();
        let out = c.compress_to_bytes(input).expect("Compression succeeds");
        let c = crate::pass1::Decompressor::new_builtin();
        let round_trip = c.decompress_to_bytes(&out).expect("Compression succeeds");
        println!("Compressed {} to {}", cert_bytes.len(), out.len());
        assert_eq!(cert_bytes, round_trip);
    }
}
