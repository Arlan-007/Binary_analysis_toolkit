from pathlib import Path

def load_binary(path: str) -> bytes:
    file = Path(path)

    if not file.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with open(file, "rb") as f:
        return f.read()


def detect_format(path: str) -> str:
    with open(path, "rb") as f:
        magic = f.read(4)

    if magic.startswith(b"\x7fELF"):
        return "ELF"

    if magic.startswith(b"MZ"):
        return "PE"

    macho_magics = [
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    ]

    if magic in macho_magics:
        return "Mach-O"

    return "Unknown"