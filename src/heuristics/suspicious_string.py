SUSPICIOUS_STRINGS = {
    "CreateRemoteThread",
    "WriteProcessMemory",
    "VirtualAllocEx",
    "IsDebuggerPresent",
    "ptrace",
    "dlopen",
}

def get_suspicious_strings(imports):
    suspicious = []