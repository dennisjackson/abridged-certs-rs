use super::tls::{CertificateEntry, CertificateMessage};
use bytes::{BufMut, Bytes, BytesMut};
use std::io::Write;

type CertIdentifier = Bytes;

mod builtins;

fn map_or_preserve_cert_entry(mut entry: CertificateEntry) -> CertificateEntry {
    entry.data = match builtins::cert_to_identifier(&entry.data) {
        Some(id) => id,
        None => entry.data,
    };
    entry
}

fn map_identifier(mut entry: CertificateEntry) -> CertificateEntry {
    entry.data = match builtins::id_to_cert(&entry.data) {
        Some(cert_data) => cert_data,
        None => entry.data,
    };
    entry
}

pub fn compress_to_bytes(cert_msg: Bytes) -> Result<BytesMut, Box<dyn std::error::Error>> {
    let output: BytesMut = BytesMut::with_capacity(cert_msg.len());
    let mut writer = output.writer();
    compress(cert_msg, &mut writer)?;
    Ok(writer.into_inner())
}

pub fn compress(
    mut cert_msg: Bytes,
    writer: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cert_msg = CertificateMessage::read_from_bytes(&mut cert_msg)?;
    cert_msg.certificate_entries = cert_msg
        .certificate_entries
        .into_iter()
        .map(map_or_preserve_cert_entry)
        .collect();
    cert_msg.write_to_bytes(writer)?;
    Ok(())
}

pub fn decompress_to_bytes(compressed_msg: Bytes) -> Result<BytesMut, Box<dyn std::error::Error>> {
    let output: BytesMut = BytesMut::with_capacity(compressed_msg.len());
    let mut writer = output.writer();
    decompress(compressed_msg, &mut writer)?;
    Ok(writer.into_inner())
}

pub fn decompress(
    mut compressed_msg: Bytes,
    writer: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cert_msg = CertificateMessage::read_from_bytes(&mut compressed_msg)?;
    cert_msg.certificate_entries = cert_msg
        .certificate_entries
        .into_iter()
        .map(map_identifier)
        .collect();
    cert_msg.write_to_bytes(writer)?;
    Ok(())
}
