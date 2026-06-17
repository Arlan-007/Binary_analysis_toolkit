#[derive(Debug, PartialEq)]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}
#[derive(Debug)]
#[allow(dead_code)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub size: u64,
    // pub bytes: Vec<u8>,
}
#[derive(Debug)]
#[allow(dead_code)]
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub architecture: String,
    pub entrypoint: u64,
    pub sections: Vec<Section>,
}
#[derive(Debug)]
#[allow(dead_code)]
pub struct Import {
    pub library: String,
    pub function: String,
}
#[derive(Debug)]
#[allow(dead_code)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub category: String,
    pub description: String,
}
#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}