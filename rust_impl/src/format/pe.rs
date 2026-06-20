use crate::models::BinaryInfo;
use crate::models::BinaryFormat;
use crate::models::Section;
pub fn get_pe_metadata(path: &str) -> Result<BinaryInfo, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let pe = goblin::pe::PE::parse(&bytes)?;

    let arch = match pe.header.coff_header.machine {
        0x14c => "x86",
        0x8664 => "x86_64",
        _ => "unknown",
    }.to_string();

    let entry = pe.entry as u64;
    let sections = pe
        .sections
        .iter()
        .map(|s| Section {
            name: s.name().unwrap_or("unknown").to_string(),
            address: s.virtual_address as u64,
            size: s.virtual_size as u64,
            bytes: s
                .data(&bytes)
                .ok()
                .flatten()
                .map(|data| data.into_owned())
                .unwrap_or_default(),
        })
        .collect();

    Ok(BinaryInfo {
        format: BinaryFormat::Pe,
        architecture: arch.to_string(),
        entrypoint: entry,
        sections,
    })
}