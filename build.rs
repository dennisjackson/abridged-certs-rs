#![feature(iter_array_chunks)]

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use serde_json;
use phf_codegen;
use hex;
use blake;

#[derive(Debug, Deserialize)]
struct IDCertTable {
    // ID -> Cert Bytes
    data: HashMap<String, String>,
}

fn hash(bytes : &Vec<u8>) -> Vec<u8> {
    let mut result_256 = [0; 32];
    blake::hash(256,bytes,&mut result_256).expect("Error hashing");
    result_256.to_vec()
}

fn wrapper(x :String) -> String {
    let mut output = "b\"".to_string();
    for c in x.chars().array_chunks::<2>() {
        output.push('\\');
        output.push('x');
        output.push(c[0]);
        output.push(c[1]);
    }
    output.push('\"');
    output
}

fn load_builtin_cert_mappings() -> impl Iterator<Item=(String,String,Vec<u8>)> {
    let jsonP = Path::new("data/").join("data.json");
    let mut file = File::open(jsonP).expect("Failed to open file");
    let mut content = String::new();
    file.read_to_string(&mut content).expect("Failed to read file");
    let table: IDCertTable = serde_json::from_str(&content).expect("Failed to deserialize JSON");
    // Should be binary hex strings. Compiler can handle the conversion. Don't need hex.
    table.data.into_iter().map(|(x,y)| (x,y.clone(),hash(&hex::decode(y).expect("Hex error"))))
}

fn main() {

    let mut id_to_cert = phf_codegen::Map::<&[u8]>::new();
    let mut hash_to_id = phf_codegen::Map::<&[u8]>::new();

    for (id,cert,fingerprint) in load_builtin_cert_mappings() {
        dbg!(&fingerprint);
        id_to_cert.entry(hex::decode(id.clone()).expect("Hex Error").leak(), &wrapper(cert));
        hash_to_id.entry(fingerprint.leak(), &wrapper(id));
    }

    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("builtin_tables.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());

    writeln!(
        &mut file,
         "static ID_TO_CERT: phf::Map<&'static [u8], &'static [u8]> = \n{};\n",
         id_to_cert.build()
    ).unwrap();

    writeln!(
        &mut file,
         "static HASH_TO_ID: phf::Map<&'static [u8], &'static [u8]> = \n{};\n",
         hash_to_id.build()
    ).unwrap();

}