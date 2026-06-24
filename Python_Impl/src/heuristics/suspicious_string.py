SUSPICIOUS_STRINGS = {
    "createremotethread",
    "writeprocessmemory",
    "virtualallocex",
    "isdebuggerpresent",
    "ptrace",
    "dlopen",
}

def get_suspicious_strings(extracted_strings):
    suspicious = []

    for item in extracted_strings:
        string_value = item.get("string") if isinstance(item, dict) else item

        if string_value and isinstance(string_value, str):
            if string_value.lower() in SUSPICIOUS_STRINGS:
                suspicious.append(item)

    return suspicious
