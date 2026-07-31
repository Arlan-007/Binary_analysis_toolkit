use crate::data::risk_signature::canonical_category_name;

/// Human-readable context for one canonical risk category.
///
/// `next_step` may contain the placeholder `{binary}`, which the report renderer replaces with
/// the analyzed path so the suggested commands can be copied and run as-is.
pub struct CategoryExplanation {
    pub category: &'static str,
    pub headline: &'static str,
    pub meaning: &'static str,
    pub benign: &'static str,
    pub next_step: &'static str,
}

pub const CATEGORY_EXPLANATIONS: &[CategoryExplanation] = &[
    // Process manipulation
    CategoryExplanation {
        category: "Process Injection",
        headline: "process injection",
        meaning: "The binary imports functions used to allocate memory inside another process, \
                  write to it, and start a thread there. That sequence is how code is made to \
                  run under a process that did not compile it.",
        benign: "Debuggers, profilers, crash handlers, anti-cheat systems and accessibility \
                 tools all inject legitimately. Some installers patch running processes too.",
        next_step: "Check whether the injection APIs are reachable from the entry point, and \
                    what buffer is written: injection of a resource or decrypted blob is much \
                    more telling than injection of a DLL path.",
    },
    CategoryExplanation {
        category: "Process Inspection",
        headline: "inspection of other processes",
        meaning: "The binary can read another process's memory. On its own this only shows the \
                  capability to look, not to modify.",
        benign: "This is exactly what debuggers, memory profilers and crash reporters do, and \
                 several monitoring agents read process memory as part of normal operation.",
        next_step: "Look at how the target process is chosen. A hard-coded process name, \
                    especially a browser or a security product, is the interesting case.",
    },
    CategoryExplanation {
        category: "Process Creation",
        headline: "child process creation",
        meaning: "The binary can start other programs. It says nothing by itself about which \
                  programs or why.",
        benign: "Extremely common. Build tools, shells, installers, launchers and anything that \
                 shells out to a helper binary will match.",
        next_step: "Search the extracted strings for the command line being built. Interpreter \
                    names, download utilities and shell one-liners are worth following.",
    },
    CategoryExplanation {
        category: "Privilege Escalation",
        headline: "privilege and token manipulation",
        meaning: "The binary manipulates access tokens or process privileges — adjusting its own \
                  rights, or adopting the security context of another user.",
        benign: "Installers, service managers, backup software and anything that legitimately \
                 needs administrative rights will use these APIs.",
        next_step: "Identify which privilege is being requested. SeDebugPrivilege alongside the \
                    process APIs above is a meaningfully different story from a plain UAC prompt.",
    },
    // Runtime loading and execution
    CategoryExplanation {
        category: "Dynamic Loading",
        headline: "runtime API resolution",
        meaning: "The binary resolves libraries and functions at runtime rather than through its \
                  import table. This is the standard way to keep sensitive API names out of \
                  static analysis.",
        benign: "Plugin systems, optional feature detection, and any program supporting several \
                 library versions load dynamically by design. It is also how most language \
                 runtimes work.",
        next_step: "Look for the function names being resolved. If they are absent from the \
                    strings as well, they are probably built or decrypted at runtime, which is \
                    itself the finding.",
    },
    CategoryExplanation {
        category: "Shell Execution",
        headline: "execution through a shell",
        meaning: "The binary runs commands through a command interpreter rather than executing a \
                  program directly. That indirection is what makes pipes, redirection and \
                  chained commands available to it.",
        benign: "Scripts, build systems and administrative tools do this constantly, usually \
                 because a shell is simply the easiest way to express the task.",
        next_step: "Recover the command string. Anything assembled at runtime, or containing a \
                    URL or an encoded blob, deserves attention.",
    },
    CategoryExplanation {
        category: "Command Execution",
        headline: "direct command execution",
        meaning: "The binary passes a command string to the operating system to run. Compared to \
                  spawning a known program, this is a broader and more easily abused capability.",
        benign: "Common in administrative utilities, wrappers and anything driven by a config \
                 file that names a command to run.",
        next_step: "Determine whether the command is a fixed literal or built from data. Fixed \
                    strings are usually readable in the strings output; built ones are not.",
    },
    // Network activity
    CategoryExplanation {
        category: "Networking",
        headline: "network activity",
        meaning: "The binary contains networking APIs, URLs or IP addresses. This covers \
                  everything from a hard-coded server to an ordinary HTTPS client.",
        benign: "Most modern software talks to the network. Update checks, telemetry, licence \
                 servers and documentation URLs compiled into help text all match, and library \
                 URLs such as gnu.org appear in almost every compiled binary.",
        next_step: "Judge the endpoints, not the count. A raw IP address, a numeric-only host, a \
                    non-standard port or a domain unrelated to the product is what matters.",
    },
    // Persistence
    CategoryExplanation {
        category: "Registry",
        headline: "Windows registry access",
        meaning: "The binary reads or writes the Windows registry, which holds both configuration \
                  and the well-known keys that make programs start automatically.",
        benign: "Nearly every Windows program stores settings in the registry, and reading it is \
                 unremarkable on its own.",
        next_step: "Look for the key paths in the extracted strings. Anything under a Run, \
                    RunOnce or Services key is a persistence claim; a product-specific settings \
                    key is not.",
    },
    CategoryExplanation {
        category: "Service Control",
        headline: "service installation or control",
        meaning: "The binary can create, start, stop or reconfigure Windows services. A service \
                  survives reboots and typically runs with high privileges, which is why this \
                  is a stronger persistence signal than most.",
        benign: "Installers, updaters and management tools for legitimate services need exactly \
                 these APIs.",
        next_step: "Find the service name and binary path being registered. A service pointing \
                    at a temporary or user-writable directory is the case worth pursuing.",
    },
    // File system
    CategoryExplanation {
        category: "File Operations",
        headline: "file system activity",
        meaning: "The binary reads, writes or deletes files. This is the weakest category here \
                  and is reported mainly so it can corroborate stronger evidence.",
        benign: "Essentially all software touches files. Treat this as context, not as a finding \
                 in its own right.",
        next_step: "Only worth pursuing alongside something else — for example file writes \
                    combined with the persistence or packing categories.",
    },
    // Anti-analysis
    CategoryExplanation {
        category: "Anti-Debugging",
        headline: "anti-debugging behaviour",
        meaning: "The binary checks whether it is being debugged. On Linux the usual method is \
                  calling ptrace(PTRACE_TRACEME) on itself, which only succeeds if nothing is \
                  already tracing the process.",
        benign: "Debuggers, crash reporters, sandboxes and licensing systems use these same \
                 mechanisms. A bare int3 is also ordinary padding between functions, so on its \
                 own it is weak evidence.",
        next_step: "Disassemble around the reported address and look at what happens when the \
                    check fails — an immediate exit, or a jump into a decryption routine, says \
                    far more than the check itself:\n\n    \
                    cargo run -- {binary} --disasm address --address <reported address>",
    },
    CategoryExplanation {
        category: "Timing",
        headline: "timing checks",
        meaning: "The binary reads a high-resolution timer. Malware uses this to notice the \
                  slowdown caused by single-stepping or emulation; the technique only matters \
                  when the result is compared against a threshold.",
        benign: "Benchmarks, profilers, schedulers, games and random-number seeding all read \
                 cycle counters. This is weak evidence in isolation.",
        next_step: "Check whether two reads are subtracted and compared. Without a comparison \
                    there is no anti-analysis check, only a clock read.",
    },
    CategoryExplanation {
        category: "Environment Inspection",
        headline: "environment fingerprinting",
        meaning: "The binary queries its host — CPU identification, system properties or \
                  environment variables. Sandbox-aware malware uses this to decide whether it is \
                  being watched.",
        benign: "CPU feature detection is normal in any binary with optimised code paths, and \
                 reading environment variables is routine configuration.",
        next_step: "Look for comparisons against known virtual-machine or sandbox artefacts: \
                    hypervisor vendor strings, VM-specific device names, or analysis tool names \
                    in the extracted strings.",
    },
    // Cryptography
    CategoryExplanation {
        category: "Cryptography",
        headline: "cryptographic API use",
        meaning: "The binary uses cryptographic routines. These are used to protect data and to \
                  hide it, and static analysis cannot distinguish the two.",
        benign: "TLS, signature verification, password hashing, licence checks and integrity \
                 checks are all ordinary uses. Most networked software matches.",
        next_step: "Interesting mainly in combination: crypto plus file enumeration suggests one \
                    thing, crypto plus high-entropy sections suggests another.",
    },
    // Credentials
    CategoryExplanation {
        category: "Credentials",
        headline: "embedded credential material",
        meaning: "Strings resembling passwords, API keys, tokens or private keys are embedded in \
                  the file. Anything compiled into a binary is readable by whoever holds it, so \
                  these are effectively public.",
        benign: "Test fixtures, placeholder values, documentation examples and public \
                 identifiers such as client IDs all match. Format-based detection cannot tell a \
                 live key from an example one.",
        next_step: "Confirm each match by eye before acting — this category is the most \
                    false-positive-prone in the toolkit. If a match is real, treat the secret as \
                    compromised and rotate it rather than removing the string.",
    },
    // Input interception
    CategoryExplanation {
        category: "Hooking",
        headline: "API or input hooking",
        meaning: "The binary installs hooks that intercept events or redirect function calls \
                  before they reach their intended handler.",
        benign: "Accessibility software, input-method editors, macro tools, screen readers, \
                 debuggers and instrumentation frameworks all hook legitimately.",
        next_step: "Identify what is hooked and where the data goes. A hook whose callback writes \
                    to a file or a socket is the keylogger case; one that only reads state is not.",
    },
    CategoryExplanation {
        category: "Input Interception",
        headline: "keyboard or input interception",
        meaning: "The binary can read keyboard or input state directly, including input directed \
                  at other applications.",
        benign: "Games poll input state constantly, and hotkey utilities, remote-desktop clients \
                 and accessibility tools all need this.",
        next_step: "Look for an accompanying write path — a log file, a buffer that is encrypted, \
                    or a network send. Interception without storage is usually just input \
                    handling.",
    },
    CategoryExplanation {
        category: "Process Enumeration",
        headline: "process enumeration",
        meaning: "The binary can list the processes running on the system.",
        benign: "Task managers, monitoring agents, installers checking for a running instance, \
                 and updaters that must close an application first all enumerate processes.",
        next_step: "Weak on its own. It becomes meaningful if the extracted strings contain names \
                    of security products or analysis tools to compare against.",
    },
    // Obfuscation, packing, entropy
    CategoryExplanation {
        category: "Packing",
        headline: "packing",
        meaning: "Section names, entropy and layout together suggest the real code is compressed \
                  or encrypted in the file and unpacked in memory at run time. That is why the \
                  string and import analysis above may look unusually empty.",
        benign: "Packing is a distribution choice, not a verdict. Commercial software ships \
                 packed to reduce size and deter casual cracking, and installers and \
                 self-extracting archives are packed by design.",
        next_step: "If a standard packer is indicated, unpack a copy and re-run the analysis — \
                    the result on the unpacked file is the one worth reading. Treat the import \
                    and string sections of this report as unreliable until then.",
    },
    CategoryExplanation {
        category: "Virtualized / Protected Binary",
        headline: "commercial protection or virtualization",
        meaning: "Section names match a commercial protector. These transform the original code \
                  into bytecode for a custom interpreter, so the real logic is not present as \
                  machine code at all.",
        benign: "This is a purchased product applied deliberately, and is common in commercial \
                 software, games and licensing-sensitive applications.",
        next_step: "Static analysis will not get much further on its own. Note which protector \
                    it is and, if the sample matters, move to dynamic analysis.",
    },
    CategoryExplanation {
        category: "Suspicious Section Layout",
        headline: "unusual section layout",
        meaning: "The section table does not look like normal compiler output — unexpected \
                  names, or a layout inconsistent with the toolchains that produce this format.",
        benign: "Custom linker scripts, embedded toolchains, post-processing steps and \
                 instrumentation all legitimately produce unusual sections.",
        next_step: "Compare against a known-good binary from the same toolchain. Use \
                    `readelf -S` or an equivalent PE section dump to see the layout in full.",
    },
    CategoryExplanation {
        category: "Obfuscated Data",
        headline: "hidden or encrypted data",
        meaning: "A section holds data that appears encrypted or otherwise deliberately \
                  unreadable, rather than the code, constants or strings that would normally \
                  occupy it.",
        benign: "Compressed resources, embedded media, licence blobs and serialised assets all \
                 look the same to entropy analysis.",
        next_step: "Check the section's size and whether anything references it. A large opaque \
                    section that the code decrypts at startup is the case worth pursuing.",
    },
    CategoryExplanation {
        category: "Unusual Data Section",
        headline: "a non-standard data section",
        meaning: "A data section carries a name outside the usual set for this format.",
        benign: "Frequently deliberate and harmless: custom sections are how many build systems \
                 embed version data, resources or metadata.",
        next_step: "Weak evidence. Worth noting only if it appears together with the entropy or \
                    packing categories.",
    },
    CategoryExplanation {
        category: "Encoded String",
        headline: "encoded strings",
        meaning: "Strings that decode cleanly as base64 or hexadecimal are embedded in the file. \
                  Encoding is not encryption — it is often used simply to keep readable text out \
                  of a plain strings dump.",
        benign: "Embedded certificates, keys, test vectors, checksums, serialised configuration \
                 and inline images are all legitimately encoded this way.",
        next_step: "Read the decoded values printed with each finding. Decoded content that is \
                    itself a URL, a path or a command is the result worth following.",
    },
    CategoryExplanation {
        category: "Entropy",
        headline: "high-entropy content",
        meaning: "Some sections or strings are far closer to random than normal code or text. \
                  Compression, encryption and packing all produce this; ordinary code does not.",
        benign: "Compressed resources, embedded archives, media files and cryptographic material \
                 raise entropy legitimately. Short strings also score high for purely \
                 statistical reasons, which is why the toolkit normalises for length.",
        next_step: "Check which sections are involved. High entropy in a resource section is \
                    routine; high entropy in the executable section is the finding that matters, \
                    and usually implies packing.",
    },
];

pub fn explanation_for(category: &str) -> Option<&'static CategoryExplanation> {
    let canonical = canonical_category_name(category);
    CATEGORY_EXPLANATIONS
        .iter()
        .find(|entry| entry.category.eq_ignore_ascii_case(canonical))
}
