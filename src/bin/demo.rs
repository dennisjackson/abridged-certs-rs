use std::{fs, path::PathBuf};

use abridged_certs;
use clap::Parser;
use base64::prelude::*;

#[derive(Parser, Debug)]
struct Cli {
    #[clap(long, short, action)]
    decompress : bool,
    #[clap(long, short, action)]
    base64 : bool,
    input_file : PathBuf,
}

fn main() {
    let args = Cli::parse();
    let mut files : Vec<PathBuf>;
    if args.input_file.is_file() {
        files = vec![args.input_file];
    } else if args.input_file.is_dir() {
        files = fs::read_dir(args.input_file).unwrap().into_iter().map(|x| PathBuf::from(x.unwrap().path())).collect();
    } else {
        panic!("Invalid path");
    }
    for f in files {
        let mut input = fs::read(f).expect("Failed to open input");
        if args.base64 {
            input = BASE64_STANDARD.decode(input).expect("Error decoding base64");
        }
        let mut output : Vec<u8>;
        if args.decompress {
            let decomp = abridged_certs::Decompressor::new_from_builtin();
            output = decomp.decompress_to_bytes(&input, 16_000).expect("Error decompressing");
        } else {
            let comp = abridged_certs::Compressor::new_from_builtin();
            output = comp.compress_to_bytes(&input).expect("Error compressing");
        }
        eprintln!("{} from {} to {} bytes", if args.decompress { "Decompressed"} else {"Compressed"} , input.len(), output.len());
        let output = BASE64_STANDARD.encode(output);
        print!("{}",output);
    }

}
