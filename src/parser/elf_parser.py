from elftools.elf.elffile import ELFFile

def get_elf_metadata(path: str):
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