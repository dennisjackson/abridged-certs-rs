use std::{io::Write, ops::Div};

use bytes::{Buf, Bytes};
use simple_error::SimpleError;

fn read_tls_vec<const WIDTH: u8>(value: &mut Bytes) -> Result<Bytes, SimpleError> {
    debug_assert!(WIDTH <= 8, "Invalid width specified");
    debug_assert!(usize::MAX as u128 <= u64::MAX as u128);

    if value.len() < WIDTH as usize {
        return Err(SimpleError::new("Not enough bytes to read length field"));
    }

    let len = value.get_uint(WIDTH as usize);
    if (value.len() as u64) < len {
        return Err(SimpleError::new("Length field longer than remaining bytes"));
    }
    if len > usize::MAX as u64 {
        return Err(SimpleError::new(
            "Vec does not fit into memory on this platform",
        ));
    }

    let vec = value.split_to(len as usize);
    Ok(vec)
}

fn write_tls_int<const WIDTH: u8>(
    size: u64,
    writer: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_assert!(WIDTH <= 4 && WIDTH > 0, "Invalid width specified");
    let max_val = (8 * WIDTH) as u32;
    if size > 2_u64.pow(max_val) - 1 {
        return Err(Box::new(SimpleError::new("Length too large for Width")));
    }

    let dropped_bytes: usize = (usize::BITS.div(8) - WIDTH as u32) as usize;
    let len_bytes = &size.to_be_bytes()[dropped_bytes..];
    writer.write_all(len_bytes)?;
    Ok(())
}

fn write_tls_vec<const WIDTH: u8>(
    value: &Bytes,
    writer: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    debug_assert!(WIDTH <= 4 && WIDTH > 0, "Invalid width specified");
    debug_assert!(usize::MAX as u128 <= u64::MAX as u128);

    write_tls_int::<WIDTH>(value.len() as u64, writer)?;
    writer.write_all(value)?;
    Ok(())
}

// RFC 8446: 4.4.2
// enum {
//     X509(0),
//     RawPublicKey(2),
//     (255)
// } CertificateType;

// struct {
//     select (certificate_type) {
//         case RawPublicKey:
//           /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
//           opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

//         case X509:
//           opaque cert_data<1..2^24-1>;
//     };
//     Extension extensions<0..2^16-1>;
// } CertificateEntry;

// struct {
//     opaque certificate_request_context<0..2^8-1>;
//     CertificateEntry certificate_list<0..2^24-1>;
// } Certificate;

#[derive(Debug)]
pub struct CertificateEntry {
    pub data: Bytes,
    pub extensions: Bytes,
}

#[derive(Debug)]
pub struct CertificateMessage {
    pub request_context: Bytes,
    pub certificate_entries: Vec<CertificateEntry>,
}

impl CertificateEntry {
    pub fn read_from_bytes(value: &mut Bytes) -> Result<CertificateEntry, SimpleError> {
        let data = read_tls_vec::<3>(value)?;
        let extensions = read_tls_vec::<2>(value)?;
        Ok(CertificateEntry { data, extensions })
    }

    pub fn write_to_bytes(
        &self,
        writer: &mut impl Write,
    ) -> Result<(), Box<dyn std::error::Error>> {
        write_tls_vec::<3>(&self.data, writer)?;
        write_tls_vec::<2>(&self.extensions, writer)?;
        Ok(())
    }

    pub fn get_size(&self) -> usize {
        3 + self.data.len() + 2 + self.extensions.len()
    }
}

impl CertificateMessage {
    pub fn read_from_bytes(mut value: &mut Bytes) -> Result<CertificateMessage, SimpleError> {
        // if value.len() < 4 {
        //     return Err(SimpleError::new("Too small for handshake header"));
        // }
        // let msg_type = value.get_u8();
        // if msg_type != 11 {
        //     return Err(SimpleError::new("Not a Certificate Message"));
        // }
        // let mut contents = read_tls_vec::<3>(value)?;
        let request_context = read_tls_vec::<1>(&mut value)?;
        let mut certificate_field = read_tls_vec::<3>(&mut value)?;
        if !value.is_empty() {
            return Err(SimpleError::new("Trailing data inside Certificate Message"));
        }
        let mut certificate_entries = Vec::with_capacity(5);
        while !certificate_field.is_empty() {
            let entry = CertificateEntry::read_from_bytes(&mut certificate_field)?;
            certificate_entries.push(entry);
        }
        Ok(CertificateMessage {
            request_context,
            certificate_entries,
        })
    }

    pub fn write_to_bytes(
        &self,
        writer: &mut impl Write,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // write_tls_int::<1>(11, writer)?;
        let ce_size = self
            .certificate_entries
            .iter()
            .map(|x| x.get_size() as u64)
            .sum();
        // let total_size = ce_size + 1 + self.request_context.len() as u64 + 3;
        // write_tls_int::<3>(total_size, writer)?;
        write_tls_vec::<1>(&self.request_context, writer)?;
        write_tls_int::<3>(ce_size, writer)?;
        for ce in &self.certificate_entries {
            ce.write_to_bytes(writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CertificateMessage;

    // Added a single byte extension field
    const CERTMSG: &str = "
        0000032b0003253082032130820209a0030201020208155a92adc2048f90300d06092a86
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
        0e3469a15941e8e2cca84bb6084636a00001ff";

    #[test]
    fn happy_path() {
        /* Borrowed from https://tls13.xargs.org/#server-certificate */
        let mut cert_hex: String = String::from(CERTMSG);
        cert_hex.retain(|x| !x.is_whitespace());
        let mut cert_bytes: bytes::Bytes = hex::decode(cert_hex).unwrap().into();
        let _ =
            CertificateMessage::read_from_bytes(&mut cert_bytes).expect("Should correctly decode");
        assert_eq!(cert_bytes.len(), 0, "nothing left over");
    }

    #[test]
    fn round_trip() {
        let mut cert_hex: String = String::from(CERTMSG);
        cert_hex.retain(|x| !x.is_whitespace());
        let cert_bytes: bytes::Bytes = hex::decode(cert_hex).unwrap().into();

        let msg = CertificateMessage::read_from_bytes(&mut cert_bytes.clone())
            .expect("Should correctly decode");

        let msg_bytes: Vec<u8> = Vec::new();
        let mut cursor = std::io::Cursor::new(msg_bytes);
        msg.write_to_bytes(&mut cursor).expect("No errors");

        let msg_bytes: bytes::Bytes = cursor.into_inner().into();
        assert_eq!(msg_bytes.len(), cert_bytes.len(), "nothing left over");
        assert_eq!(msg_bytes, cert_bytes);
    }

    #[test]
    fn large_integers() {
        let msg_bytes: Vec<u8> = Vec::new();
        let mut cursor = std::io::Cursor::new(msg_bytes);
        assert!(super::write_tls_int::<1>(u8::MAX as u64 + 1,&mut cursor).is_err());
        assert!(super::write_tls_int::<2>(u16::MAX as u64 + 1,&mut cursor).is_err());
        assert!(super::write_tls_int::<3>(2_u64.pow(24) + 1,&mut cursor).is_err());
        assert!(super::write_tls_int::<4>(u32::MAX as u64 + 1,&mut cursor).is_err());
    }

}

mod datatests {

#[datatest::files("data/certificate_messages", {
  input in r"^(.*)"
})]
fn sample_test(input: &[u8]) {
  let mut bytes = bytes::Bytes::copy_from_slice(input);
  let msg =
  super::CertificateMessage::read_from_bytes(&mut bytes).expect("Should correctly decode");
  assert_eq!(bytes.len(), 0, "nothing left over");

  let msg_bytes: Vec<u8> = Vec::new();
  let mut cursor = std::io::Cursor::new(msg_bytes);
  msg.write_to_bytes(&mut cursor).expect("No errors");

  let msg_bytes: bytes::Bytes = cursor.into_inner().into();
  assert_eq!(msg_bytes.len(), input.len(), "nothing left over");
  assert_eq!(msg_bytes, input);
}
}