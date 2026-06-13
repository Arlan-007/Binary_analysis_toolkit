import pefile

def get_pe_metadata(path: str):
    with open(path, "rb") as f:
        pe = pefile.PE(path)

        arch =  pe.FILE_HEADER.Machine
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