import pefile
from elftools.elf.elffile import ELFFile
from parser.binary_loader import detect_format

def get_metadata(path: str):
    fmt = detect_format(path)

    if fmt == "ELF":
        with open(path, "rb") as f:
            elf = ELFFile(f)

            arch = elf["e_machine"]
            entry = hex(elf["e_entry"])
            sections = [
                {
                    "name": section.name,
                    "address": section["sh_addr"],
                    "size": section["sh_size"]
                }
                for section in elf.iter_sections()
            ]

            return {
                "arch": arch,
                "entry": entry,
                "sections": sections
            }

    elif fmt == "PE":
        with open(path, "rb") as f:
            pe = pefile.PE(path)

            arch = pe.FILE_HEADER.Machine
            entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            sections = [
                {
                    "name": section.Name.decode(errors="ignore").rstrip("\x00"),
                    "address": section.VirtualAddress,
                    "size": section.Misc_VirtualSize
                }
                for section in pe.sections
            ]

            return {
                "arch": arch,
                "entry": entry,
                "sections": sections
            }