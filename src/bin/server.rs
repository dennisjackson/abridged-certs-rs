use std::env;
use std::error::Error as StdError;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::ops::Deref;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use lazy_static::lazy_static;

lazy_static! {
    static ref COMPRESSOR : abridged_certs::Compressor = abridged_certs::Compressor::new_from_builtin();
}


fn main() -> Result<(), Box<dyn StdError>> {
    let mut args = env::args();
    args.next();
    let cert_file = args
        .next()
        .expect("missing certificate file argument");
    let private_key_file = args
        .next()
        .expect("missing private key file argument");

    let certs = CertificateDer::pem_file_iter(cert_file)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();
    let private_key = PrivateKeyDer::from_pem_file(private_key_file).unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;

    config.cert_compressors = vec![(COMPRESSOR.deref())];

    let listener = TcpListener::bind(format!("[::]:{}", 4443)).unwrap();
    let (mut stream, _) = listener.accept()?;

    let mut conn = rustls::ServerConnection::new(Arc::new(config))?;
    conn.complete_io(&mut stream)?;

    conn.writer()
        .write_all(b"Hello from the server")?;
    conn.complete_io(&mut stream)?;
    let mut buf = [0; 64];
    let len = conn.reader().read(&mut buf)?;
    println!("Received message from client: {:?}", &buf[..len]);

    Ok(())
}