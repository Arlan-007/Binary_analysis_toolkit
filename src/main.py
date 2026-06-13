import typer
from parser.binary_loader import detect_format

app = typer.Typer()

@app.command()
def analyze(path: str):
    fmt = detect_format(path)

    print(f"Format: {fmt}")

if __name__ == "__main__":
    app()