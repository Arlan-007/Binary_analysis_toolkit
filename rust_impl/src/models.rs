#[derive(Debug)]
#[derive(PartialEq)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}
#[derive(Debug)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub size: u64,
}
#[derive(Debug)]
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub architecture: String,
    pub entrypoint: u64,
    pub sections: Vec<Section>,
}
#[derive(Debug)]
pub struct Import {
    pub library: String,
    pub function: String,
}