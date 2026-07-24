import math
from pathlib import Path

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0.0
    total_bytes = len(data)

    for count in byte_counts:
        if count > 0:
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)

def check_file_entropy(file_path: str, threshold: float = 7.2) -> dict:

    try:

        path = Path(file_path)
        if not path.is_file():
            return {"error": "File not found", "is_suspicious": False}

        binary_data = path.read_bytes()
        entropy_score = calculate_entropy(binary_data)

        is_suspicious = entropy_score >= threshold

        return {
            "file_name": path.name,
            "entropy": entropy_score,
            "is_suspicious": is_suspicious,
            "description": "High entropy detected (likely packed or encrypted)" if is_suspicious else "Normal entropy signature"
        }
    except Exception as e:
        return {"error": str(e), "is_suspicious": False}
