use crate::models::BinaryFormat;
use crate::models::Import;

pub fn get_imports(path: &str , fmt: BinaryFormat) -> Result<Vec<Import>, Box<dyn std::error::Error>> {
    let mut imports = Vec::new();

    if fmt == BinaryFormat::Elf {
        let bytes = std::fs::read(path)?;
        let elf = goblin::elf::Elf::parse(&bytes)?;

        for sym in &elf.dynsyms {
            if !sym.is_import() {
                continue;
            }

            if let Some(import) = elf.dynstrtab.get_at(sym.st_name) {
                if import.is_empty() {
                    continue;
                }
                imports.push(Import {
                    library: import.to_string(),
                    function: import.to_string(),
                });
            }
        }
    }
    else if fmt == BinaryFormat::Pe {
        let bytes = std::fs::read(path)?;
        let pe = goblin::pe::PE::parse(&bytes)?;

        for import in &pe.imports {
            imports.push(Import {
                library: import.dll.to_string(),
                function: import.name.to_string(),
            });
        }
    }

    Ok(imports)
}

pub fn get_needed_libraries(path: &str, fmt: BinaryFormat) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut libs = Vec::new();

    if fmt == BinaryFormat::Elf {
        let bytes = std::fs::read(path)?;
        let elf = goblin::elf::Elf::parse(&bytes)?;
        for lib in &elf.libraries {
            libs.push(lib.to_string());
        }
    }

    Ok(libs)
}
