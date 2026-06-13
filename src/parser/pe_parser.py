import pefile


def get_pe_architecture(path: str):
    pe = pefile.PE(path)

    return pe.FILE_HEADER.Machine

def get_pe_starting(path: str):
    pe = pefile.PE(path)

    return pe.OPTIONAL_HEADER.AddressOfEntryPoint

def get_pe_sections(path: str):
    pe = pefile.PE(path)

    return [
        {
            "name": section.Name.decode(errors="ignore").rstrip("\x00"),
            "address": section.VirtualAddress,
            "size": section.Misc_VirtualSize
        }
        for section in pe.sections
    ]