mod models;
mod format;
mod analysis;
mod data;
use std::env;

use crate::models::{BinaryFormat, RiskSummary};

use format::detect::detect_format;
use format::elf::get_elf_metadata;
use format::pe::get_pe_metadata;

use analysis::string::extract_strings;
use analysis::import::get_imports;
use analysis::heuristics::{suspicious_imports, suspicious_url, suspicious_ip, suspicious_credentials, suspicious_sections};
use analysis::heuristics::{detect_encoded_strings, high_entropy_strings, high_entropy_sections, detect_packed_binary};
use analysis::risk::calculate_risk_score;
use analysis::entropy::calculate_entropy;

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
    // println!("{:#?}", info);

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
    println!("Found {} suspicious imports", suspicious_imports.len());
    // for import in suspicious_imports {
    //     println!("{:#?}", import);
    // }

    let suspicious_url = suspicious_url(&strings);
    println!("Found {} URL", suspicious_url.len());
    // for url in suspicious_url {
    //     println!("{:#?}", url);
    // }

    let suspicious_ip = suspicious_ip(&strings);
    println!("Found {} IPs", suspicious_ip.len());
    // for ip in suspicious_ip {
    //     println!("{:#?}", ip);
    // }

    let credentials = suspicious_credentials(&strings);
    println!("Found {} credentials", credentials.len());
    // for credential in credentials {
    //     println!("{:#?}", credential);
    // }

    let suspicious_sections = suspicious_sections(&info.sections);
    println!("Found {} Suspicious Sections", suspicious_sections.len());
    // for sections in suspicious_sections {
    //     println!("{:#?}", sections);
    // }

    let encodings = detect_encoded_strings(&strings);
    println!("Found {} encodings", encodings.len());
    // for encoding in encodings {
    //     println!("{:#?}", encoding);
    // }

    let entropy_string = high_entropy_strings(&strings);
    println!("Found {} high entropy strings", entropy_string.len());
    // for ent in entropy_string {
    //     println!("{:#?}", ent);
    // }

    let entropy_section = high_entropy_sections(&info.sections);
    println!("Found {} high entropy section", entropy_section.len());
    // for ent in entropy_section {
    //     println!("{:#?}", ent);
    // }

    let packed_binary = detect_packed_binary(&info.sections);
    for bin in &packed_binary {
        println!("{:#?}", bin);
    }

    let mut all_findings = Vec::new();

    all_findings.extend(suspicious_imports.clone());
    all_findings.extend(suspicious_url.clone());
    all_findings.extend(suspicious_ip.clone());
    all_findings.extend(credentials.clone());
    all_findings.extend(suspicious_sections.clone());
    all_findings.extend(encodings.clone());
    all_findings.extend(entropy_string.clone());
    all_findings.extend(entropy_section.clone());
    all_findings.extend(packed_binary.clone());

    // for finding in &all_findings {
    //     println!("{:#?}", finding);
    // }

    let risk = calculate_risk_score(&all_findings,);
    println!("{:#?}", risk);
}
