
SUSPICIOUS_IMPORTS = {
    "createremotethread",
    "writeprocessmemory",
    "virtualallocex",
    "isdebuggerpresent",
    "ptrace",
    "dlopen",
}

def get_suspicious_imports(imports):
    suspicious = []

    for imp in imports:
        func_name = imp.get("function")
        if func_name and isinstance(func_name, str):
            if func_name.lower() in SUSPICIOUS_IMPORTS:
                suspicious.append(imp)

    return suspicious
