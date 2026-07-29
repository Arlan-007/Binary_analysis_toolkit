class ReportGenerator:
    def __init__(self, binary_data):
        self.data = binary_data

    def generate_markdown(self):
        strings = self.data.get('strings', []) or []
        imports = self.data.get('imports', []) or []

        report = [
            f"# Binary Analysis Report: {self.data.get('file_name', 'Unknown')}",
            "\n## Metadata",
            f"- Architecture: {self.data.get('arch', 'N/A')}",
            f"- File Type: {self.data.get('file_type', 'N/A')}",
            "\n## Suspicious Indicators",
            f"- Status: {'SUSPICIOUS' if self.data.get('is_suspicious') else 'Normal'}",
            f"- Entropy: {self.data.get('entropy', 0)}",
            f"- Description: {self.data.get('description', 'None')}",
            "\n## Extracted Strings",
            "\n".join([f"- {s}" for s in strings[:10]]) if strings else "- No strings extracted.",
            "\n## Imported Functions",
            "\n".join([f"- {i}" for i in imports]) if imports else "- No imports found."
        ]
        return "\n".join(report)

    def save_report(self, output_path="analysis_report.md"):
        with open(output_path, "w") as f:
            f.write(self.generate_markdown())