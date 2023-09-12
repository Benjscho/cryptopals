use std::{fs::read_to_string, str::from_utf8};

use clap::{Args, Parser, Subcommand};
use set_1::xor::repeating_key_xor;

use crate::byte_util::hex_encode;

pub mod set_1;
pub mod set_2;
pub mod byte_util;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    XorCipher(XorCipher)
}

#[derive(Args)]
struct XorCipher {
    #[arg(long, short)]
    file: Option<String>,
    #[arg(long, short)]
    key: String,
    #[arg(long, short)]
    data: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::XorCipher(c) => {
            if let Some(file) = &c.file {
                let f = read_to_string(file);
                // Unholy nesting batman
                // I should probably make some of these methods 'impls' for u8
                println!("{}", from_utf8(&hex_encode(&repeating_key_xor(f.unwrap().as_bytes(), &c.key.as_bytes()))).unwrap());
            } else {
                for d in &c.data {
                    println!("{}", from_utf8(&hex_encode(&repeating_key_xor(&d.as_bytes(), &c.key.as_bytes()))).unwrap());
                }
            }
        }
    }
}
