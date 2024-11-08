
// #[cfg(all(feature ="nightly-features"))]
// #[feature(custom_test_frameworks)]


/* Expose internal functions to fuzzer */
#[cfg(fuzzing)]
pub mod tls;
#[cfg(not(fuzzing))]
mod tls;

use rustls::compress::{CertCompressor, CertDecompressor};
use bytes::{BufMut, Bytes};
use std::io::Write;

pub mod pass1;
pub mod pass2;

#[derive(Debug)]
pub struct Compressor {
    p1: pass1::Compressor,
    p2: pass2::Compressor,
}

impl Compressor {
    pub fn new(p1lookup: pass1::IdFunc) -> Self {
        Compressor {
            p1: pass1::Compressor::new(p1lookup),
            p2: pass2::Compressor::new(),
        }
    }

    pub fn new_from_builtin() -> Self {
        Compressor {
            p1: pass1::Compressor::new_builtin(),
            p2: pass2::Compressor::new(),
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

impl CertCompressor for Compressor {
    fn compress(
        &self,
        input: Vec<u8>,
        level: rustls::compress::CompressionLevel,
    ) -> Result<Vec<u8>, rustls::compress::CompressionFailed> {
        let res = self.compress_to_bytes(&input);
        if res.is_err() {
            Err(rustls::compress::CompressionFailed)
        } else {
            Ok(res.unwrap())
        }
    }

    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::CertificateCompressionAlgorithm::Unknown(9999)
    }
}

#[derive(Debug)]
pub struct Decompressor {
    p1: pass1::Decompressor,
    p2: pass2::Decompressor,
}

impl Decompressor {
    pub fn new(p1_lookup: pass1::CertFunc) -> Self {
        Decompressor {
            p1: pass1::Decompressor::new(p1_lookup),
            p2: pass2::Decompressor::new(),
        }
    }

    pub fn new_from_builtin() -> Self {
        Decompressor {
            p1: pass1::Decompressor::new_builtin(),
            p2: pass2::Decompressor::new(),
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

impl CertDecompressor for Decompressor {
    fn decompress(&self, input: &[u8], mut output: &mut [u8]) -> Result<(), rustls::compress::DecompressionFailed> {
        let res = self.decompress_to_bytes(input,output.len() as u32);
        if res.is_ok() {
            let res = res.unwrap();
            output.write_all(&res).unwrap();
            Ok(())
        } else {
            Err(rustls::compress::DecompressionFailed)
        }
    }

    fn algorithm(&self) -> rustls::CertificateCompressionAlgorithm {
        rustls::CertificateCompressionAlgorithm::Unknown(9999)
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

    const COMPRESSED_MESSAGE : &[u8] = &[0x41,0xdc,0x13,0x00,0x30,0xc3,0xd3,0xcd,0x3f,0x75,0x13,0xf4,0x6a,0x6b,0x60,0x03,0xe9,0x4f,0x61,0xf0,0xa6,0xae,0xa7,0x1e,0x86,0x19,0x87,0xff,0xe8,0xd5,0xf8,0x11,0x07,0x98,0xe0,0x3b,0xf4,0x05,0x32,0x0b,0x0c,0xc3,0xd2,0x6d,0x0e,0xc4,0x3e,0x23,0x28,0xb5,0x02,0x95,0xde,0x6e,0x04,0x41,0xd8,0x17,0x08,0x7b,0x0e,0x0a,0xb0,0xc7,0xa0,0x00,0x3d,0xdd,0x87,0x22,0x30,0x82,0xb0,0x62,0xb9,0xb4,0x67,0x25,0x4d,0x53,0x5b,0x57,0x06,0xaa,0x75,0xdf,0xdf,0x11,0xe9,0x8d,0x7e,0x09,0x18,0x70,0x1a,0xd9,0x12,0xb3,0x92,0xef,0x0c,0x30,0x4c,0x47,0x80,0x00,0x89,0x48,0x07,0x68,0x70,0xd4,0x19,0xc3,0xd9,0x10,0x67,0x47,0x22,0x27,0x60,0x97,0x5e,0x5a,0x36,0x06,0xab,0xe0,0x24,0xa9,0x44,0x61,0xe3,0x98,0xc0,0x84,0xf4,0xb8,0x24,0x43,0x80,0x2e,0x71,0x50,0x06,0x82,0x5c,0x0c,0x24,0x15,0x40,0x22,0x92,0x01,0x50,0x21,0x01,0x55,0x0f,0xc1,0xc8,0x09,0xb2,0x07,0xe0,0x24,0xb2,0x03,0x56,0x17,0x8e,0x2e,0x89,0xa8,0xba,0x2a,0x80,0x02,0x58,0xf4,0x0a,0x00,0x8e,0xd0,0x02,0x98,0x09,0xd2,0x99,0xb4,0x48,0x01,0xfd,0x5e,0xe8,0xa4,0xc5,0x83,0xbb,0x99,0x1f,0x27,0xfa,0x0a,0x3c,0xd8,0xfc,0xdf,0x41,0xd6,0x20,0x8f,0xbd,0xfc,0x54,0x67,0x7a,0xd5,0x90,0xf4,0xbc,0x44,0x26,0x89,0x48,0x7d,0xcf,0x88,0xc6,0xb1,0xb1,0xf0,0x4a,0xc7,0xcc,0x3f,0x72,0xcd,0xa9,0x06,0xc6,0x67,0xef,0x98,0xb5,0x28,0x7a,0x1b,0x09,0x5d,0xa9,0xce,0x96,0xc1,0x43,0x9b,0x87,0xec,0x17,0x36,0x9e,0x08,0xf3,0x9a,0xc4,0x95,0x9d,0x5a,0x85,0x4e,0xe6,0xe9,0x5c,0xff,0xe8,0x12,0xb0,0xfc,0x83,0x2a,0x6a,0xf5,0xe7,0xda,0xdd,0x3f,0xc4,0xe5,0xfb,0x2a,0x2d,0xcf,0xe0,0xdf,0x5f,0xb4,0x1d,0xbf,0xcf,0xba,0xf0,0xb6,0xdc,0x4e,0x92,0x29,0x7d,0x72,0xa6,0x7c,0xa4,0x36,0xf3,0x9a,0xad,0x6f,0x30,0x9f,0x9f,0x6b,0xdd,0x8d,0x9c,0x97,0x76,0x0d,0xaa,0xcc,0x57,0x6d,0x0e,0xf3,0x50,0xdf,0x85,0x63,0x8f,0xcc,0xdf,0x58,0x61,0x53,0xc8,0xff,0x25,0xa6,0x93,0x9f,0xdc,0x6d,0x79,0x34,0xcb,0x2f,0xdd,0x60,0x8d,0x3b,0xc8,0x20,0xbc,0xbb,0x69,0xec,0x27,0xf8,0xb4,0x30,0x9f,0x72,0xa7,0x2b,0x87,0xf8,0x64,0xe0,0x50,0xf8,0x71,0xe9,0x14,0x5b,0x4a,0xd7,0x03,0xc1,0x75,0x13,0x5d,0x41,0xfa,0x97,0xde,0xc5,0xeb,0x1b,0xb1,0x36,0xd2,0xe7,0xff,0xe6,0x49,0x9e,0x49,0x7d,0x9d,0x20,0x7f,0x89,0x55,0xf5,0x51,0xfe,0x12,0x83,0xc8,0xd3,0xd1,0x75,0x2a,0x82,0xc7,0x3d,0x56,0x7e,0x4b,0x7a,0x11,0xa7,0x9a,0x9a,0xfe,0xdf,0xbf,0x18,0x9f,0x55,0x5c,0x0c,0x27,0x0b,0x53,0xeb,0x90,0x28,0x32,0xa2,0xe9,0xf9,0x15,0x1d,0x4f,0xce,0xf5,0x22,0x28,0x0c,0xc1,0x83,0x05,0x08,0x03,0x28,0x40,0x68,0x00,0x23,0x8e,0x3a,0x0b,0x30,0xc1,0xf0,0x7f,0x0c,0x43,0x11,0x42,0x1f,0x10,0x60,0x59,0x02,0x8b,0x52,0x9e,0x5a,0x0e,0x87,0x09,0x04,0x2a,0x14,0x9e,0xd9,0x08,0xa0,0x37,0xa1,0xd9,0x5c,0x5c,0x04,0x40,0x0d,0x30,0xce,0xc6,0xd8,0x93,0xf8,0x48,0x03,0x27,0x45,0xe8,0x8b,0x6c,0xbb,0x2d,0x47,0xcc,0xce,0xcf,0x17,0x5c,0x68,0xd6,0xb5,0x04,0x42,0xb8,0x26,0x86,0x71,0x03,0xce,0x3c,0x76,0x76,0xc5,0x45,0xae,0x55,0x37,0x97,0xd3,0x33,0x76,0x34,0x94,0x67,0x42,0xb3,0xdd,0x95,0xec,0x07,0xc7,0x80,0xf3,0xee,0x19,0x18,0xc6,0xcc,0x81,0x29,0x10,0x59,0xf3,0x00,0x5c,0xc2,0xf1,0xf2,0xfb,0x09,0xca,0x8a,0xb1,0xbf,0x8a,0x55,0x02,0x13,0x22,0x2c,0x88,0x9a,0x91,0x90,0x12,0x4e,0x5c,0xb8,0xad,0x04,0x38,0xcf,0x2e,0x65,0xc1,0x98,0x00,0x43,0x41,0x76,0xd0,0x6c,0xba,0x2a,0x61,0x8c,0x1e,0xd0,0x02,0x6a,0x1c,0x0f,0xcd,0xa7,0x87,0x11,0xb8,0xbf,0x0b,0x86,0xd3,0xca,0xe1,0x30,0x06,0x5f,0x4b,0x47,0x30,0x04,0xcb,0xff,0x8a,0xe5,0x7f,0x82,0x3e,0x40,0x29,0xd0,0xbb,0xb3,0x17,0x82,0xae,0xde,0xe6,0x3d,0x77,0xd4,0x6b,0xb5,0x7b,0xe9,0x2c,0xdb,0x00,0xa9,0xd4,0x24,0x6b,0xeb,0xcd,0xbd,0x43,0x7b,0x33,0x77,0x93,0x78,0xa1,0xe5,0x4e,0x08,0x82,0xab,0x27,0xa2,0xbb,0x58,0x20,0x08,0x43,0x21,0x53,0x60,0x8c,0x08,0x87,0xf6,0x10,0x62,0xcb,0x97,0x6a,0x3b,0xe6,0xde,0x2e,0xaf,0x30,0x66,0x7a,0xe0,0xd2,0xaf,0xd4,0xc5,0xa6,0x4b,0xfe,0x4f,0x2b,0x9b,0xf6,0x2d,0x09,0x34,0xfc,0xcc,0x44,0x44,0xa0,0x6f,0x13,0xc5,0x27,0xf8,0xfa,0x5f,0xdc,0xd0,0x89,0x11,0x5d,0xab,0xfb,0xb9,0x21,0x9e,0x3c,0x3a,0x1d,0xf0,0xad,0xf3,0x7f,0x56,0x42,0xe9,0x59,0xeb,0xa1,0x89,0x03,0x03,0x3a,0xac,0xe5,0x98,0x9a,0xac,0xab,0xb0,0x9e,0x67,0x53,0x09,0x3c,0xf1,0x7f,0x14,0xad,0xd0,0x1b,0xb6,0x87,0x5f,0x8e,0x6f,0x43,0x0c,0x0a,0x09,0xb1,0x0f,0x7f,0x5d,0xe1,0x02,0xa1,0xe7,0xc8,0x6a,0xd6,0xae,0xa1,0x83,0x3b,0x7d,0x1c,0xe2,0xed,0x2b,0x9a,0x1d,0x0d,0xcf,0xbb,0x6f,0x7d,0x94,0x19,0x57,0xbc,0x63,0xdd,0xeb,0xc3,0xf2,0x34,0xdd,0x65,0x28,0xb5,0xf3,0x1f,0x9e,0x1e,0xf8,0x4d,0xff,0x4b,0xeb,0x2b,0xad,0xfd,0x35,0x87,0x8b,0x26,0x4f,0x18,0x9f,0xd0,0x97,0xb5,0x24,0x8b,0x57,0xf1,0xea,0xdc,0x78,0x8d,0xb3,0x0a,0xfc,0xbb,0xe6,0x52,0x36,0x08,0xdd,0x17,0x84,0x21,0x9f,0xa2,0x85,0xc7,0x0d,0xbc,0x9b,0xd8,0x0d,0x9a,0x67,0xf6,0x6e,0x93,0x63,0xc0,0xb4,0xf8,0xd5,0x89,0xcb,0xa2,0x6d,0x1c,0xf1,0xfb,0xdf,0x7d,0x54,0x1f,0x7d,0xff,0xfa,0xdc,0xec,0x8c,0x16,0xaf,0xac,0xc1,0xaa,0xbc,0x8c,0xb4,0xf9,0xe7,0x63,0x71,0x75,0x11,0x93,0xd5,0xc5,0x49,0xcd,0x32,0x3f,0x82,0x74,0x1c,0xfe,0xb6,0x29,0x2f,0xb5,0x4c,0x1e,0xd5,0x5e,0x51,0x61,0x94,0xfb,0x54,0x43,0xda,0x6e,0xfd,0xfe,0x2a,0x3c,0x79,0x35,0xeb,0x88,0xec,0x2f,0x97,0x7b,0x65,0xe7,0xd4,0xfc,0x07,0x44,0x12,0x05,0xce,0x50,0x05,0xb7,0x4e,0x2c,0x48,0x37,0x3e,0x20,0x1b,0x5e,0x69,0x38,0x62,0x11,0x62,0x7e,0x56,0x9b,0xca,0x18,0xb5,0x9b,0x8e,0xe1,0x48,0x8b,0x30,0x3c,0xff,0xed,0xdc,0x00,0xff,0x0f,0x69,0xf8,0xb9,0x99,0x59,0xbf,0x59,0xff,0xae,0xb2,0x96,0x48,0xcc,0xcf,0xbf,0x79,0xc2,0x39,0x95,0xf1,0x4a,0xc2,0xeb,0xaa,0x97,0x29,0x2e,0x72,0xf9,0xcb,0x7f,0x6f,0x03,0xe9,0xcb,0xef,0x1f,0x88,0x69,0x86,0x3c,0x67,0x97,0x7c,0xe8,0x4c,0x7f,0xbc,0xe5,0x3c,0x46,0x6c,0xeb,0xa2,0x14,0x3f,0xa1,0xfd,0xce,0x92,0x25,0x9d,0xfe,0x32,0xfd,0x94,0x96,0x47,0xb8,0x04,0x75,0x0b,0xda,0x77,0xb4,0x17,0xa7,0x56,0xe3,0xbf,0x3e,0x3d,0xee,0x15,0xc6,0xc6,0x77,0x6a,0x0f,0x0d,0xe5,0x90,0x79,0xfd,0xef,0xd6,0xcb,0x78,0x89,0x11,0xf7,0xb4,0x07,0x72,0x5d,0x3b,0x0e,0x1c,0x9a,0xbb,0x94,0x8d,0xb4,0x6c,0xf2,0x83,0x9c,0xc5,0x25,0xfe,0xf3,0x30,0x03,0x4f,0x70,0x97,0x17,0x34,0xc4,0xd0,0xff,0xd8,0x4b,0x08,0x32,0x00,0x03];

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
    fn test_decompressor() {
        let c = Decompressor::new_from_builtin();
        c.decompress_to_bytes(&COMPRESSED_MESSAGE, 16000)
            .expect("Decompression succeeds");
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
