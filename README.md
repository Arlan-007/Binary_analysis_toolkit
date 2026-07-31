# Binary Analysis and Reverse Engineering Toolkit

A lightweight educational toolkit for static binary analysis and reverse
engineering. The Rust implementation supports ELF and PE inspection,
signature-based indicators, risk scoring, and bounded Capstone disassembly for
x86-64 and AArch64 binaries.

> **Status:** Capstone milestone complete. The disassembler is linear and does
> not attempt decompilation or full control-flow recovery.

## Features

### Binary inspection

- ELF and PE format detection
- Architecture and entry-point metadata
- Section, import, library, export, and symbol extraction
- Printable ASCII and UTF-16LE strings

### Static indicators

- Suspicious imports, URLs, IPv4 addresses, and credentials
- Base64, hexadecimal, and high-entropy strings
- Suspicious sections, section entropy, and packer indicators
- Category-based risk scoring

### Capstone disassembly

- x86-64 and AArch64 decoding
- `.text`, entry-point, symbol, and explicit address navigation
- Exact symbol/export labels
- Direct call and branch target annotations
- Format-aware anti-debug, timing, environment, and direct `ptrace` indicators
- Deterministic code-feature counts, summarised in the generated report

## Running

```bash
cd rust_impl
cargo build
cargo run -- samples/pe/pe-sample
```

Normal analysis performs a bounded `.text` scan for instruction findings and
code features without printing the instruction listing.

```bash
# Show the start of .text.
cargo run -- samples/pe/pe-sample --disasm text

# Show code from the entry point.
cargo run -- samples/elf/elf-sample-clean --disasm entrypoint

# Show code from an exact symbol/export.
cargo run -- samples/elf/elf-sample-clean --disasm symbol --symbol main

# Show code from an explicit address.
cargo run -- samples/pe/pe-sample --disasm address --address 0x1000

# Bound displayed output.
cargo run -- samples/pe/pe-sample --disasm text --max-bytes 512 --max-instructions 50
```

Displayed disassembly defaults to 4096 input bytes and 200 instructions. The
display selection does not alter the fixed instruction-analysis scope or risk
score.

## Reports

Every run writes a Markdown report into a `report/` directory beside wherever
you ran the command — so `cargo run` from `rust_impl/` collects them in
`rust_impl/report/` and leaves `samples/` exactly as checked in. The file is
named `<binary>.report.md`. Use `--report PATH` to send it somewhere else. Two
binaries with the same file name in different directories will overwrite each
other's report; pass `--report` to keep both. The report
groups findings by category, explains what each category means and how it can
arise benignly, reports how much of `.text` actually decoded, suggests a
concrete next step per category, states the analyzer's limitations, and closes
with an annotated listing of the first 40 instructions from the entry point.
Rendering is deterministic: the same binary always produces the same report.

```bash
# Writes rust_impl/report/pe-sample.report.md
cargo run -- samples/pe/pe-sample

# Choose the destination.
cargo run -- samples/pe/pe-sample --report /tmp/pe-sample.md
```

## Address convention

- ELF section, symbol, entry-point, and instruction addresses are virtual
  addresses (`va`).
- PE section, export, entry-point, and instruction addresses are relative
  virtual addresses (`rva`).

Address, symbol, and entry-point modes select whichever file-backed section
contains the requested address. AArch64 starting addresses must be four-byte
aligned. Starting in the middle of an x86-64 instruction can still produce a
syntactically valid but semantically misleading linear decode.

## Instruction analysis

The fixed `.text` scan extracts calls, direct branches, returns, syscalls,
traps, timing instructions, and conservative anti-debug patterns. Repeated
low-confidence instructions such as padding `INT3` bytes are counted in code
features but reported as one de-duplicated finding.

Linux syscall-number rules only run for ELF binaries:

- x86-64: `ptrace` syscall number 101
- AArch64: `ptrace` syscall number 117

Generic `syscall` and `svc` instructions are counted but do not create a risk
finding without context.

## Testing

```bash
cd rust_impl
cargo fmt
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

The disassembly tests cover both architectures, custom sections, entry points,
symbol labels, direct targets, alignment, invalid ranges, format-aware syscall
rules, and deterministic code features.

## Limitations

This project performs bounded linear disassembly. It does not build a complete
control-flow graph, recover all functions from stripped binaries, resolve
indirect calls, execute code, or decompile binaries.

## Disclaimer

This toolkit is intended for educational cybersecurity work and does not
replace a professional malware-analysis or reverse-engineering platform.
