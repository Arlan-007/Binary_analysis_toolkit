from elftools.elf.elffile import ELFFile


def get_elf_architecture(path: str) -> str:
    with open(path, "rb") as f:
        elf = ELFFile(f)

        return elf["e_machine"]

def get_elf_starting(path: str):
    with open(path, "rb") as f:
        elf = ELFFile(f)

        return hex(elf["e_entry"])

def get_elf_sections(path: str):
    with open(path, "rb") as f:
        elf = ELFFile(f)

        return [
            {
                "name": section.name,
                "address": section["sh_addr"],
                "size": section["sh_size"]
            }
            for section in elf.iter_sections()
        ]