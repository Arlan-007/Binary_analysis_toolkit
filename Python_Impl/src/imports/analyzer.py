import pefile
from elftools.elf.elffile import ELFFile
from parser.binary_loader import detect_format

def get_imports(path):
    fmt = detect_format(path)
    if fmt == "PE":
        pe = pefile.PE(path)
        imports = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for dll in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = dll.dll.decode()
                for imp in dll.imports:
                    imports.append({
                        "library": dll_name,
                        "function": imp.name.decode() if imp.name else None
                    })
        return imports

    elif fmt == "ELF":
        with open(path, "rb") as f:
            elf = ELFFile(f)

        imports = []

        with open(path, "rb") as f:
            elf = ELFFile(f)
            dynsym = elf.get_section_by_name(".dynsym")

            if dynsym is None:
                return imports

            for symbol in dynsym.iter_symbols():
                if symbol.name:
                    imports.append({
                        "function": symbol.name
                    })

        return imports