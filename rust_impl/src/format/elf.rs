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
            let name = elf
                .shdr_strtab
                .get_at(section.sh_name)
                .unwrap_or("unknown");

            let section_bytes = if section.sh_type == goblin::elf::section_header::SHT_NOBITS {
                Vec::new()
            } else {
                let start = section.sh_offset as usize;
                let end = start.saturating_add(section.sh_size as usize);
                bytes.get(start..end).unwrap_or(&[]).to_vec()
            };

            Section {
                name: name.to_string(),
                address: section.sh_addr,
                size: section.sh_size,
                bytes: section_bytes,
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