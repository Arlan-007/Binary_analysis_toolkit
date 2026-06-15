SUSPICIOUS_IMPORTS = {
    "CreateRemoteThread",
    "WriteProcessMemory",
    "VirtualAllocEx",
    "IsDebuggerPresent",
    "ptrace",
    "dlopen",
}

def get_suspicious_imports(imports):
    suspicious = []

    for imp in imports:
        if imp["function"] in SUSPICIOUS_IMPORTS:
            suspicious.append(imp)

    return suspicious