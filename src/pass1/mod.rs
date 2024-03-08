use super::tls::{CertificateEntry, CertificateMessage};
use bytes::{BufMut, Bytes, BytesMut};
use std::io::Write;

type CertIdentifier = Bytes;

mod builtins;

type IdFunc = fn(&Bytes) -> Option<CertIdentifier>;
type CertFunc = fn(&CertIdentifier) -> Option<Bytes>;

pub struct Compressor {
    lookup: IdFunc,
}

impl Compressor {
    pub fn new(lookup: IdFunc) -> Self {
        Compressor { lookup }
    }

    pub fn new_builtin() -> Self {
        Compressor { lookup: builtins::cert_to_identifier}
    }

    fn map_or_preserve_cert_entry(&self, mut entry: CertificateEntry) -> CertificateEntry {
        entry.data = match (self.lookup)(&entry.data) {
            Some(id) => id,
            None => entry.data,
        };
        entry
    }

    pub fn compress_to_bytes(
        &self,
        cert_msg: Bytes,
    ) -> Result<BytesMut, Box<dyn std::error::Error>> {
        let output: BytesMut = BytesMut::with_capacity(cert_msg.len());
        let mut writer = output.writer();
        self.compress(cert_msg, &mut writer)?;
        Ok(writer.into_inner())
    }

    pub fn compress(
        &self,
        mut cert_msg: Bytes,
        writer: &mut impl Write,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

struct Decompressor {
    lookup: CertFunc,
}

impl Decompressor {
    pub fn new(lookup: CertFunc) -> Self {
        Decompressor { lookup }
    }

    pub fn new_builtin() -> Self {
        Decompressor { lookup: builtins::id_to_cert}
    }

    fn map_identifier(&self, mut entry: CertificateEntry) -> CertificateEntry {
        entry.data = match (self.lookup)(&entry.data) {
            Some(cert_data) => cert_data,
            None => entry.data,
        };
        entry
    }

    pub fn decompress_to_bytes(
        &self,
        compressed_msg: Bytes,
    ) -> Result<BytesMut, Box<dyn std::error::Error>> {
        let output: BytesMut = BytesMut::with_capacity(compressed_msg.len());
        let mut writer = output.writer();
        self.decompress(compressed_msg, &mut writer)?;
        Ok(writer.into_inner())
    }

    pub fn decompress(
        &self,
        mut compressed_msg: Bytes,
        writer: &mut impl Write,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
