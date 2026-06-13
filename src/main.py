import typer
from parser.binary_loader import detect_format
from parser.pe_parser import get_pe_architecture , get_pe_starting , get_pe_sections , get_pe_metadata
from parser.elf_parser import get_elf_metadata

app = typer.Typer()

@app.command()
def analyze(path: str):
    fmt = detect_format(path)

    if fmt == "ELF":
        metadata = get_elf_metadata(path)

    elif fmt == "PE":
        metadata = get_pe_metadata(path)


    print(f"Format: {fmt}")
    print(f"Architecture: {metadata["arch"]}")
    print(f"Entrypoint: {metadata["entry"]}")
    print(f"Sections:")
    for section in metadata["sections"]:
        print(
            f"{section['name']:15}"
            f"addr=0x{section['address']:x} "
            f"size={section['size']}"
        )

if __name__ == "__main__":
    app()