import typer
from parser.binary_loader import detect_format
from parser.parser import get_metadata
from strings.extractor import extract_strings

app = typer.Typer()

@app.command()
def analyze(path: str):
    fmt = detect_format(path)
    metadata = get_metadata(path)
    strings = extract_strings(path)


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
    print(f"Strings:")
    for s in strings:
        print(
            f"[{s['section']}] "
            f"{s['string']}"
        )


if __name__ == "__main__":
    app()