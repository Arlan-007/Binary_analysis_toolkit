import pefile
from elftools.elf.elffile import ELFFile
from parser.binary_loader import detect_format
import binary2strings as b2s

PE_SECTIONS = {
    ".data",
    ".rdata",
    ".text"
}

ELF_SECTIONS = {
    ".rodata",
    ".data",
    ".text"
}


def get_sections(path):
    fmt = detect_format(path)
    sections = []

    if fmt == "PE":
        pe = pefile.PE(path)

        for section in pe.sections:
            name = (
                section.Name
                .decode(errors="ignore")
                .rstrip("\x00")
            )
            if name in PE_SECTIONS:
                sections.append({
                    "name": name,
                    "data": section.get_data()
                })

    elif fmt == "ELF":
        with open(path, "rb") as f:
            elf = ELFFile(f)

            for section in elf.iter_sections():
                if section.name in ELF_SECTIONS:
                    sections.append({
                        "name": section.name,
                        "data": section.data()
                    })

    return sections

def extract_data(data, section_name):
    results = []

    for string_text, offset, string_type, info in b2s.extract_all_strings(data):
        string_text = string_text.strip()
        if len(string_text) < 4:
            continue
        if string_text.isdigit():
            continue
        if len(set(string_text)) <= 2:
            continue

        results.append({
            "section": section_name,
            "string": string_text,
            "offset": offset,
            "type": str(string_type)
        })

    return results

def extract_strings(path):
    sections = get_sections(path)
    all_strings = []
    for section in sections:
        all_strings.extend(
            extract_data(
                section["data"],
                section["name"]
            )
        )

    seen = set()
    result = []

    for item in all_strings:
        key = item["string"]

        if key not in seen:
            seen.add(key)
            result.append(item)

    return result