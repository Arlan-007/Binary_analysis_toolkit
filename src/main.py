import typer
from parser.binary_loader import detect_format
from parser.pe_parser import get_pe_architecture , get_pe_starting , get_pe_sections
from parser.elf_parser import get_elf_architecture , get_elf_starting , get_elf_sections

app = typer.Typer()

@app.command()
def analyze(path: str):
    fmt = detect_format(path)

    if fmt == "ELF":
        arch = get_elf_architecture(path)
        starting = get_elf_starting(path)
        sections = get_elf_sections(path)

    elif fmt == "PE":
        arch = get_pe_architecture(path)
        starting = get_pe_starting(path)
        sections = get_pe_sections(path)


    print(f"Format: {fmt}")
    print(f"Architecture: {arch}")
    print(f"Entrypoint: {starting}")
    print(f"Sections:")
    for section in sections:
        print(
            f"{section['name']:15}"
            f"addr=0x{section['address']:x} "
            f"size={section['size']}"
        )

if __name__ == "__main__":
    app()