
// #[cfg(all(feature ="nightly-features"))]
// #[feature(custom_test_frameworks)]


/* Expose internal functions to fuzzer */
#[cfg(fuzzing)]
pub mod tls;
#[cfg(not(fuzzing))]
mod tls;


pub mod pass1;
pub mod pass2;

pub struct Compressor<'a> {
    p1: pass1::Compressor,
    p2: pass2::Compressor<'a>,
}

impl<'a> Compressor<'a> {
    pub fn new(p1lookup: pass1::IdFunc, p2_dict: &[u8]) -> Self {
        Compressor {
            p1: pass1::Compressor::new(p1lookup),
            p2: pass2::Compressor::new(p2_dict),
        }
    }

    pub fn new_from_builtin() -> Self {
        Compressor {
            p1: pass1::Compressor::new_builtin(),
            p2: pass2::Compressor::new_from_builtin(),
        }
    }

    pub fn compress_to_bytes(
        &self,
        cert_msg: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let p1 = self.p1.compress_to_bytes(cert_msg)?;
        let p2 = self.p2.compress_to_bytes(&p1)?;
        Ok(p2)
    }
}

pub struct Decompressor<'a> {
    p1: pass1::Decompressor,
    p2: pass2::Decompressor<'a>,
}

impl<'a> Decompressor<'a> {
    pub fn new(p1_lookup: pass1::CertFunc, p2_dict: &[u8]) -> Self {
        Decompressor {
            p1: pass1::Decompressor::new(p1_lookup),
            p2: pass2::Decompressor::new(p2_dict),
        }
    }

    pub fn new_from_builtin() -> Self {
        Decompressor {
            p1: pass1::Decompressor::new_builtin(),
            p2: pass2::Decompressor::new_from_builtin(),
        }
    }

    pub fn decompress_to_bytes(
        &self,
        comp_msg: &[u8],
        max_size: u32,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let p2 = self.p2.decompress_to_bytes(comp_msg, max_size)?;
        // TODO: Inefficient and needs the size limit enforcing
        let p1 = self.p1.decompress_to_bytes(&p2)?;
        Ok(p1)
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
        let c = Compressor::new_from_builtin();
        let out = c
            .compress_to_bytes(&cert_bytes)
            .expect("Compression succeeds");
        println!("Compressed to {} from {}", out.len(), cert_bytes.len());
    }

    #[test]
    fn round_trip_happy() {
        let mut cert_hex: String = String::from(CERTMSG);
        cert_hex.retain(|x| !x.is_whitespace());
        let cert_bytes = hex::decode(cert_hex).unwrap();
        let c = Compressor::new_from_builtin();
        let out = c
            .compress_to_bytes(&cert_bytes)
            .expect("Compression succeeds");
        let c = Decompressor::new_from_builtin();
        let round_trip = c
            .decompress_to_bytes(&out, 16000)
            .expect("Compression succeeds");
        assert_eq!(cert_bytes, round_trip);
    }

    #[test]
    fn size_limits() {
        let mut cert_hex: String = String::from(CERTMSG);
        cert_hex.retain(|x| !x.is_whitespace());
        let cert_bytes = hex::decode(cert_hex).unwrap();
        let c = Compressor::new_from_builtin();
        let out = c
            .compress_to_bytes(&cert_bytes)
            .expect("Compression succeeds");
        let c = Decompressor::new_from_builtin();
        let _ = c
            .decompress_to_bytes(&out, 100)
            .expect_err("Shouldn't be enough space!");
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
        let c = crate::Compressor::new_from_builtin();
        let out = c.compress_to_bytes(input).expect("Compression succeeds");
        let c = crate::Decompressor::new_from_builtin();
        let round_trip = c
            .decompress_to_bytes(&out, 16000)
            .expect("Decompression succeeds");
        println!("Compressed {} to {}", cert_bytes.len(), out.len());
        assert_eq!(cert_bytes, round_trip);
    }
}
