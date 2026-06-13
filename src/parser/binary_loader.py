def detect_format(path: str):
    with open(path, "rb") as f:
        magic = f.read(4)

    if magic.startswith(b"\x7fELF"):
        return "ELF"

    if magic.startswith(b"MZ"):
        return "PE"

    return "Unknown"