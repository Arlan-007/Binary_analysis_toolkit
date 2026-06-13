from pathlib import Path
import typer

app = typer.Typer()

@app.command()
def analyze(path: str):
    file = Path(path)

    if not file.exists():
        print(f"File not found: {path}")
        raise typer.Exit(1)

    print(f"Name: {file.name}")
    print(f"Size: {file.stat().st_size} bytes")

if __name__ == "__main__":
    app()