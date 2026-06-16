mod models;
mod format;
mod analysis;
mod data;
use std::env;

use crate::models::BinaryFormat;

use format::detect::detect_format;
use format::elf::get_elf_metadata;
use format::pe::get_pe_metadata;
use analysis::string::extract_strings;
use analysis::import::get_imports;
use analysis::heuristics::suspicious_imports;
use analysis::heuristics::suspicious_url;

fn main() {
    let path = env::args()
        .nth(1)
        .expect("Usage: cargo run -- <binary>");

    let fmt = match detect_format(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    let info = match fmt {
        BinaryFormat::Elf => get_elf_metadata(&path).expect("Failed to extract metadata"),
        BinaryFormat::Pe => get_pe_metadata(&path).expect("Failed to extract metadata"),
        BinaryFormat::MachO => {
            eprintln!("Mach-O not implemented");
            return;
        }
        BinaryFormat::Unknown => {
            eprintln!("Unknown format");
            return;
        }
    };
    println!("{:#?}", info);

    let strings = extract_strings(&path).expect("Failed to extract strings");
    println!("Found {} strings", strings.len());
    // for string in strings {
    //     println!("{}", string);
    // }

    let imports = get_imports(&path , fmt).expect("Failed to extract imports");
    println!("Found {} imports", imports.len());
    // for import in imports {
    //     println!("{:#?}", import);
    // }

    let suspicious_imports = suspicious_imports(&imports);
    println!("Found {} suspicious_imports", suspicious_imports.len());
    // for import in suspicious_imports {
    //     println!("{:#?}", import);
    // }

    let suspicious_url = suspicious_url(&strings);
    println!("Found {} URL", suspicious_url.len());
    for url in suspicious_url {
        println!("{:#?}", url);
    }
}
