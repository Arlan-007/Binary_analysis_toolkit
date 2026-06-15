import typer
from parser.binary_loader import detect_format
from parser.parser import get_metadata
from strings.extractor import extract_strings
from imports.analyzer import get_imports
from heuristics.suspicious_imports import get_suspicious_imports
from heuristics.suspicious_string import get_suspicious_strings


app = typer.Typer()

@app.command()
def analyze(path: str):
    fmt = detect_format(path)
    metadata = get_metadata(path)
    strings = extract_strings(path)
    imports = get_imports(path)
    suspicious_strings = get_suspicious_strings(strings)
    suspicious_imports = get_suspicious_imports(imports)


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

    print(f"Imports:")
    if fmt == "ELF":
        for i in imports:
            print(
                f"[{i['function']}] "
            )
    elif fmt == "PE":
        for i in imports:
            print(
                f"[{i['library']}] "
                f"{i['function']}"
            )


if __name__ == "__main__":
    app()