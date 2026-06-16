use crate::models::Severity;

#[derive(Debug, Clone, PartialEq)]
pub struct ImportRule {
    pub function: &'static str,
    pub severity: Severity,
    pub category: &'static str,
    pub description: &'static str,
}

pub const IMPORT_RULES: &[ImportRule] = &[

    // Process injection / memory manipulation

    ImportRule {
        function: "VirtualAlloc",
        severity: Severity::High,
        category: "Process Injection",
        description: "Allocates memory, sometimes used for shellcode staging or unpacking.",
    },
    ImportRule {
        function: "VirtualAllocEx",
        severity: Severity::Critical,
        category: "Process Injection",
        description: "Allocates memory in a remote process.",
    },
    ImportRule {
        function: "VirtualProtect",
        severity: Severity::High,
        category: "Process Injection",
        description: "Changes memory protection, often used to make memory executable.",
    },
    ImportRule {
        function: "VirtualProtectEx",
        severity: Severity::Critical,
        category: "Process Injection",
        description: "Changes memory protection in a remote process.",
    },
    ImportRule {
        function: "WriteProcessMemory",
        severity: Severity::Critical,
        category: "Process Injection",
        description: "Writes data into another process's memory.",
    },
    ImportRule {
        function: "ReadProcessMemory",
        severity: Severity::Medium,
        category: "Process Inspection",
        description: "Reads memory from another process, used in debuggers and malware tooling.",
    },
    ImportRule {
        function: "CreateRemoteThread",
        severity: Severity::Critical,
        category: "Process Injection",
        description: "Creates a thread in another process.",
    },
    ImportRule {
        function: "CreateRemoteThreadEx",
        severity: Severity::Critical,
        category: "Process Injection",
        description: "Creates a thread in another process with extended options.",
    },
    ImportRule {
        function: "NtCreateThreadEx",
        severity: Severity::Critical,
        category: "Process Injection",
        description: "Native API often used for remote thread creation.",
    },
    ImportRule {
        function: "OpenProcess",
        severity: Severity::High,
        category: "Process Injection",
        description: "Opens another process for manipulation or inspection.",
    },
    ImportRule {
        function: "OpenProcessToken",
        severity: Severity::High,
        category: "Privilege Escalation",
        description: "Accesses process tokens, sometimes used in privilege abuse.",
    },
    ImportRule {
        function: "DuplicateTokenEx",
        severity: Severity::High,
        category: "Privilege Escalation",
        description: "Duplicates access tokens and may be involved in impersonation.",
    },

    // Dynamic loading / API resolution

    ImportRule {
        function: "LoadLibraryA",
        severity: Severity::Medium,
        category: "Dynamic Loading",
        description: "Loads a DLL at runtime.",
    },
    ImportRule {
        function: "LoadLibraryW",
        severity: Severity::Medium,
        category: "Dynamic Loading",
        description: "Loads a DLL at runtime using wide strings.",
    },
    ImportRule {
        function: "LoadLibraryExA",
        severity: Severity::Medium,
        category: "Dynamic Loading",
        description: "Extended DLL loading function.",
    },
    ImportRule {
        function: "LoadLibraryExW",
        severity: Severity::Medium,
        category: "Dynamic Loading",
        description: "Extended DLL loading function using wide strings.",
    },
    ImportRule {
        function: "GetProcAddress",
        severity: Severity::Medium,
        category: "Dynamic Loading",
        description: "Resolves function addresses at runtime.",
    },
    ImportRule {
        function: "GetModuleHandleA",
        severity: Severity::Low,
        category: "Dynamic Loading",
        description: "Retrieves a module handle, often used with dynamic API resolution.",
    },
    ImportRule {
        function: "GetModuleHandleW",
        severity: Severity::Low,
        category: "Dynamic Loading",
        description: "Retrieves a module handle using wide strings.",
    },
    ImportRule {
        function: "GetModuleHandleExA",
        severity: Severity::Low,
        category: "Dynamic Loading",
        description: "Extended module handle retrieval.",
    },
    ImportRule {
        function: "GetModuleHandleExW",
        severity: Severity::Low,
        category: "Dynamic Loading",
        description: "Extended module handle retrieval using wide strings.",
    },

    // Code execution / command launching

    ImportRule {
        function: "CreateProcessA",
        severity: Severity::High,
        category: "Process Creation",
        description: "Creates a new process.",
    },
    ImportRule {
        function: "CreateProcessW",
        severity: Severity::High,
        category: "Process Creation",
        description: "Creates a new process using wide strings.",
    },
    ImportRule {
        function: "WinExec",
        severity: Severity::High,
        category: "Process Creation",
        description: "Legacy process execution function.",
    },
    ImportRule {
        function: "ShellExecuteA",
        severity: Severity::Medium,
        category: "Shell Execution",
        description: "Runs a shell operation or launches a program.",
    },
    ImportRule {
        function: "ShellExecuteW",
        severity: Severity::Medium,
        category: "Shell Execution",
        description: "Runs a shell operation or launches a program using wide strings.",
    },
    ImportRule {
        function: "system",
        severity: Severity::High,
        category: "Command Execution",
        description: "Runs a command via the system shell.",
    },

    // Networking / download / C2-style behavior

    ImportRule {
        function: "InternetOpenA",
        severity: Severity::Medium,
        category: "Networking",
        description: "Initializes WinINet for network communication.",
    },
    ImportRule {
        function: "InternetOpenW",
        severity: Severity::Medium,
        category: "Networking",
        description: "Initializes WinINet for network communication using wide strings.",
    },
    ImportRule {
        function: "InternetConnectA",
        severity: Severity::Medium,
        category: "Networking",
        description: "Connects to a remote internet resource.",
    },
    ImportRule {
        function: "InternetConnectW",
        severity: Severity::Medium,
        category: "Networking",
        description: "Connects to a remote internet resource using wide strings.",
    },
    ImportRule {
        function: "HttpOpenRequestA",
        severity: Severity::Medium,
        category: "Networking",
        description: "Creates an HTTP request using WinINet.",
    },
    ImportRule {
        function: "HttpOpenRequestW",
        severity: Severity::Medium,
        category: "Networking",
        description: "Creates an HTTP request using WinINet and wide strings.",
    },
    ImportRule {
        function: "HttpSendRequestA",
        severity: Severity::Medium,
        category: "Networking",
        description: "Sends an HTTP request.",
    },
    ImportRule {
        function: "HttpSendRequestW",
        severity: Severity::Medium,
        category: "Networking",
        description: "Sends an HTTP request using wide strings.",
    },
    ImportRule {
        function: "URLDownloadToFileA",
        severity: Severity::High,
        category: "Networking",
        description: "Downloads a file from a URL.",
    },
    ImportRule {
        function: "URLDownloadToFileW",
        severity: Severity::High,
        category: "Networking",
        description: "Downloads a file from a URL using wide strings.",
    },
    ImportRule {
        function: "WSAStartup",
        severity: Severity::Low,
        category: "Networking",
        description: "Initializes Winsock networking.",
    },
    ImportRule {
        function: "socket",
        severity: Severity::Low,
        category: "Networking",
        description: "Creates a network socket.",
    },
    ImportRule {
        function: "connect",
        severity: Severity::Low,
        category: "Networking",
        description: "Connects a socket to a remote endpoint.",
    },
    ImportRule {
        function: "send",
        severity: Severity::Low,
        category: "Networking",
        description: "Sends data over a socket.",
    },
    ImportRule {
        function: "recv",
        severity: Severity::Low,
        category: "Networking",
        description: "Receives data from a socket.",
    },
    ImportRule {
        function: "closesocket",
        severity: Severity::Low,
        category: "Networking",
        description: "Closes a Winsock socket.",
    },

    // Registry persistence / configuration

    ImportRule {
        function: "RegOpenKeyExA",
        severity: Severity::Medium,
        category: "Registry",
        description: "Opens a registry key.",
    },
    ImportRule {
        function: "RegOpenKeyExW",
        severity: Severity::Medium,
        category: "Registry",
        description: "Opens a registry key using wide strings.",
    },
    ImportRule {
        function: "RegCreateKeyExA",
        severity: Severity::Medium,
        category: "Registry",
        description: "Creates or opens a registry key.",
    },
    ImportRule {
        function: "RegCreateKeyExW",
        severity: Severity::Medium,
        category: "Registry",
        description: "Creates or opens a registry key using wide strings.",
    },
    ImportRule {
        function: "RegSetValueExA",
        severity: Severity::High,
        category: "Registry",
        description: "Writes a registry value, often used for persistence.",
    },
    ImportRule {
        function: "RegSetValueExW",
        severity: Severity::High,
        category: "Registry",
        description: "Writes a registry value using wide strings.",
    },
    ImportRule {
        function: "RegDeleteValueA",
        severity: Severity::Medium,
        category: "Registry",
        description: "Deletes a registry value.",
    },
    ImportRule {
        function: "RegDeleteValueW",
        severity: Severity::Medium,
        category: "Registry",
        description: "Deletes a registry value using wide strings.",
    },
    ImportRule {
        function: "RegCloseKey",
        severity: Severity::Low,
        category: "Registry",
        description: "Closes an open registry key handle.",
    },

    // File and system manipulation

    ImportRule {
        function: "CreateFileA",
        severity: Severity::Low,
        category: "File Operations",
        description: "Creates or opens a file.",
    },
    ImportRule {
        function: "CreateFileW",
        severity: Severity::Low,
        category: "File Operations",
        description: "Creates or opens a file using wide strings.",
    },
    ImportRule {
        function: "DeleteFileA",
        severity: Severity::Low,
        category: "File Operations",
        description: "Deletes a file.",
    },
    ImportRule {
        function: "DeleteFileW",
        severity: Severity::Low,
        category: "File Operations",
        description: "Deletes a file using wide strings.",
    },
    ImportRule {
        function: "MoveFileA",
        severity: Severity::Low,
        category: "File Operations",
        description: "Moves or renames a file.",
    },
    ImportRule {
        function: "MoveFileW",
        severity: Severity::Low,
        category: "File Operations",
        description: "Moves or renames a file using wide strings.",
    },
    ImportRule {
        function: "CopyFileA",
        severity: Severity::Low,
        category: "File Operations",
        description: "Copies a file.",
    },
    ImportRule {
        function: "CopyFileW",
        severity: Severity::Low,
        category: "File Operations",
        description: "Copies a file using wide strings.",
    },
    ImportRule {
        function: "SetFileAttributesA",
        severity: Severity::Low,
        category: "File Operations",
        description: "Changes file attributes.",
    },
    ImportRule {
        function: "SetFileAttributesW",
        severity: Severity::Low,
        category: "File Operations",
        description: "Changes file attributes using wide strings.",
    },
    ImportRule {
        function: "GetTempPathA",
        severity: Severity::Low,
        category: "File Operations",
        description: "Gets the temporary directory path.",
    },
    ImportRule {
        function: "GetTempPathW",
        severity: Severity::Low,
        category: "File Operations",
        description: "Gets the temporary directory path using wide strings.",
    },
    ImportRule {
        function: "GetTempFileNameA",
        severity: Severity::Low,
        category: "File Operations",
        description: "Creates a temporary file name.",
    },
    ImportRule {
        function: "GetTempFileNameW",
        severity: Severity::Low,
        category: "File Operations",
        description: "Creates a temporary file name using wide strings.",
    },

    // Service control / persistence

    ImportRule {
        function: "OpenSCManagerA",
        severity: Severity::High,
        category: "Service Control",
        description: "Opens the service control manager.",
    },
    ImportRule {
        function: "OpenSCManagerW",
        severity: Severity::High,
        category: "Service Control",
        description: "Opens the service control manager using wide strings.",
    },
    ImportRule {
        function: "CreateServiceA",
        severity: Severity::Critical,
        category: "Service Control",
        description: "Creates a Windows service, often used for persistence.",
    },
    ImportRule {
        function: "CreateServiceW",
        severity: Severity::Critical,
        category: "Service Control",
        description: "Creates a Windows service using wide strings.",
    },
    ImportRule {
        function: "StartServiceA",
        severity: Severity::High,
        category: "Service Control",
        description: "Starts a Windows service.",
    },
    ImportRule {
        function: "StartServiceW",
        severity: Severity::High,
        category: "Service Control",
        description: "Starts a Windows service using wide strings.",
    },
    ImportRule {
        function: "OpenServiceA",
        severity: Severity::Medium,
        category: "Service Control",
        description: "Opens an existing Windows service.",
    },
    ImportRule {
        function: "OpenServiceW",
        severity: Severity::Medium,
        category: "Service Control",
        description: "Opens an existing Windows service using wide strings.",
    },

    // Anti-debugging / analysis evasion

    ImportRule {
        function: "IsDebuggerPresent",
        severity: Severity::High,
        category: "Anti-Debugging",
        description: "Checks whether a debugger is attached.",
    },
    ImportRule {
        function: "CheckRemoteDebuggerPresent",
        severity: Severity::High,
        category: "Anti-Debugging",
        description: "Checks whether another process is being debugged.",
    },
    ImportRule {
        function: "OutputDebugStringA",
        severity: Severity::Medium,
        category: "Anti-Debugging",
        description: "Writes output to the debugger if one is attached.",
    },
    ImportRule {
        function: "OutputDebugStringW",
        severity: Severity::Medium,
        category: "Anti-Debugging",
        description: "Writes output to the debugger using wide strings.",
    },
    ImportRule {
        function: "GetTickCount",
        severity: Severity::Low,
        category: "Timing",
        description: "Used for timing checks or anti-analysis delays.",
    },
    ImportRule {
        function: "QueryPerformanceCounter",
        severity: Severity::Low,
        category: "Timing",
        description: "High resolution timer, sometimes used in anti-analysis logic.",
    },
    ImportRule {
        function: "Sleep",
        severity: Severity::Low,
        category: "Timing",
        description: "Delays execution and can be used for anti-analysis.",
    },

    // Crypto / obfuscation-adjacent

    ImportRule {
        function: "CryptAcquireContextA",
        severity: Severity::Medium,
        category: "Cryptography",
        description: "Acquires a cryptographic provider context.",
    },
    ImportRule {
        function: "CryptAcquireContextW",
        severity: Severity::Medium,
        category: "Cryptography",
        description: "Acquires a cryptographic provider context using wide strings.",
    },
    ImportRule {
        function: "CryptEncrypt",
        severity: Severity::Medium,
        category: "Cryptography",
        description: "Encrypts data using CryptoAPI.",
    },
    ImportRule {
        function: "CryptDecrypt",
        severity: Severity::Medium,
        category: "Cryptography",
        description: "Decrypts data using CryptoAPI.",
    },
    ImportRule {
        function: "CryptGenRandom",
        severity: Severity::Medium,
        category: "Cryptography",
        description: "Generates random bytes, often used in key generation.",
    },

    // Credential / browser / sensitive data access

    ImportRule {
        function: "CredEnumerateA",
        severity: Severity::High,
        category: "Credentials",
        description: "Enumerates credentials from Windows Credential Manager.",
    },
    ImportRule {
        function: "CredEnumerateW",
        severity: Severity::High,
        category: "Credentials",
        description: "Enumerates credentials from Windows Credential Manager using wide strings.",
    },
    ImportRule {
        function: "CredReadA",
        severity: Severity::High,
        category: "Credentials",
        description: "Reads stored credentials.",
    },
    ImportRule {
        function: "CredReadW",
        severity: Severity::High,
        category: "Credentials",
        description: "Reads stored credentials using wide strings.",
    },
    ImportRule {
        function: "CryptUnprotectData",
        severity: Severity::Critical,
        category: "Credentials",
        description: "Decrypts protected data, sometimes abused to recover secrets.",
    },

    // Miscellaneous but useful indicators

    ImportRule {
        function: "SetWindowsHookExA",
        severity: Severity::Critical,
        category: "Hooking",
        description: "Installs a hook procedure, used by keyloggers and GUI interception tools.",
    },
    ImportRule {
        function: "SetWindowsHookExW",
        severity: Severity::Critical,
        category: "Hooking",
        description: "Installs a hook procedure using wide strings.",
    },
    ImportRule {
        function: "RegisterHotKey",
        severity: Severity::Medium,
        category: "Input Interception",
        description: "Registers global hotkeys.",
    },
    ImportRule {
        function: "FindWindowA",
        severity: Severity::Low,
        category: "Environment Inspection",
        description: "Searches for a window by title/class.",
    },
    ImportRule {
        function: "FindWindowW",
        severity: Severity::Low,
        category: "Environment Inspection",
        description: "Searches for a window by title/class using wide strings.",
    },
    ImportRule {
        function: "GetForegroundWindow",
        severity: Severity::Low,
        category: "Environment Inspection",
        description: "Gets the active foreground window.",
    },
    ImportRule {
        function: "EnumProcesses",
        severity: Severity::Low,
        category: "Process Enumeration",
        description: "Enumerates running processes.",
    },
    ImportRule {
        function: "Process32FirstW",
        severity: Severity::Low,
        category: "Process Enumeration",
        description: "Enumerates processes using the ToolHelp snapshot API.",
    },
    ImportRule {
        function: "Process32NextW",
        severity: Severity::Low,
        category: "Process Enumeration",
        description: "Continues process enumeration using the ToolHelp snapshot API.",
    },
];