use crate::models::{BinaryFormat, Symbol, SymbolKind};
use goblin::elf::sym::{STT_FUNC, STT_OBJECT};

fn elf_symbol_kind(st_type: u8) -> SymbolKind {
    match st_type {
        STT_FUNC => SymbolKind::Function,
        STT_OBJECT => SymbolKind::Object,
        _ => SymbolKind::Other,
    }
}

pub fn get_exports(path: &str, fmt: BinaryFormat) -> Result<Vec<Symbol>, Box<dyn std::error::Error>> {
    let mut exports = Vec::new();

    match fmt {
        BinaryFormat::Elf => {
            let bytes = std::fs::read(path)?;
            let elf = goblin::elf::Elf::parse(&bytes)?;

            for sym in &elf.dynsyms {
                if sym.is_import() {
                    continue;
                }
                if sym.st_value == 0 {
                    continue;
                }
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if name.is_empty() {
                        continue;
                    }
                    exports.push(Symbol {
                        name: name.to_string(),
                        address: sym.st_value,
                        kind: elf_symbol_kind(sym.st_type()),
                    });
                }
            }
        }
        BinaryFormat::Pe => {
            let bytes = std::fs::read(path)?;
            let pe = goblin::pe::PE::parse(&bytes)?;

            for export in &pe.exports {
                if let Some(name) = export.name {
                    exports.push(Symbol {
                        name: name.to_string(),
                        address: export.rva as u64,
                        kind: SymbolKind::Function,
                    });
                }
            }
        }
        _ => {}
    }

    Ok(exports)
}

pub fn get_symbols(path: &str, fmt: BinaryFormat) -> Result<Vec<Symbol>, Box<dyn std::error::Error>> {
    let mut symbols = Vec::new();
    if fmt == BinaryFormat::Elf {
        let bytes = std::fs::read(path)?;
        let elf = goblin::elf::Elf::parse(&bytes)?;

        for sym in &elf.syms {
            let st_type = sym.st_type();
            if st_type != STT_FUNC && st_type != STT_OBJECT {
                continue;
            }
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name.is_empty() {
                    continue;
                }
                symbols.push(Symbol {
                    name: name.to_string(),
                    address: sym.st_value,
                    kind: elf_symbol_kind(st_type),
                });
            }
        }
    }
    Ok(symbols)
}
