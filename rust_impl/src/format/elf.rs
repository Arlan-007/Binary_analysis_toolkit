use crate::models::BinaryInfo;
use crate::models::BinaryFormat;
use crate::models::Section;
pub fn get_elf_metadata(path: &str) -> Result<BinaryInfo, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let elf = goblin::elf::Elf::parse(&bytes)?;

    let arch = elf.header.e_machine;
    let entry = elf.entry;
    let sections = elf
        .section_headers
        .iter()
        .map(|section| {
            Section {
                name: section.sh_name.to_string(),
                address: section.sh_addr,
                size: section.sh_size,
            }
        })
        .collect();

    Ok(BinaryInfo {
        format: BinaryFormat::Elf,
        architecture: arch.to_string(),
        entrypoint: entry,
        sections,
    })
}