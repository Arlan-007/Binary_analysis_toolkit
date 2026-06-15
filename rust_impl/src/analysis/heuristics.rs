const SUSPICIOUS: &[&str] = &[
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
];
