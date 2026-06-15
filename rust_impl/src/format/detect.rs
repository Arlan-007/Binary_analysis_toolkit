use std::fs::File;
use std::io::Read;

use crate::models::BinaryFormat;
pub fn detect_format(path: &str) -> std::io::Result<BinaryFormat> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 4];

    file.read_exact(&mut magic)?;

    if magic == [0x7f, b'E' , b'L' , b'F'] {
        return Ok(BinaryFormat::Elf);
    }
    if magic[0] == b'M' && magic[1] == b'Z' {
        return Ok(BinaryFormat::Pe);
    }
    if magic == [0xFE , 0xED , 0xFA , 0xCE]
        || magic == [0xFE , 0xED , 0xFA , 0xCF]
        || magic == [0xCE , 0xFA , 0xED , 0xFE]
        || magic == [0xCF , 0xFA , 0xED , 0xfe]
    {
        return Ok(BinaryFormat::MachO);
    }

    Ok(BinaryFormat::Unknown)
}