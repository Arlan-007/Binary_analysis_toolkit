# Binary Analysis and Reverse Engineering Toolkit

A lightweight, modular toolkit for static binary analysis and reverse engineering, developed for educational use in cybersecurity. The project supports analysis of **ELF** and **PE** executables, extracting structural information, suspicious indicators, and heuristic-based risk assessments through a command-line interface.

> **Status:** Active Development

---

## Features

### Binary Inspection

* ELF and PE format detection
* Binary metadata extraction
* Section enumeration
* Raw section byte extraction

### String Analysis

* Printable string extraction
* URL detection
* IPv4 address detection
* Hardcoded credential detection
* Base64 detection
* Hex-encoded string detection
* High-entropy string detection

### Import Analysis

* Imported function extraction
* Categorized suspicious import detection
* Behavioral grouping of imported APIs

### Entropy Analysis

* Shannon entropy calculation
* Section entropy analysis
* High-entropy section detection
* Packed binary heuristics
* Known packer section detection

### Risk Assessment

* Category-based risk scoring
* Severity classification
* Configurable signature-based scoring engine

---

## Project Structure

```text
binary_analysis_toolkit/
│
├── python_impl/          # Original Python implementation
│
└── rust_impl/
    ├── src/
    │   ├── analysis/
    │   ├── data/
    │   ├── format/
    │   ├── models.rs
    │   └── main.rs
    │
    ├── samples/
    └── Cargo.toml
```

---

## Current Analysis Pipeline

```text
Input Binary
      │
      ▼
Format Detection
      │
      ▼
Metadata Extraction
      │
      ▼
Section Extraction
      │
      ▼
String Extraction
      │
      ▼
Import Extraction
      │
      ▼
Heuristic Analysis
      │
      ▼
Entropy Analysis
      │
      ▼
Packed Binary Detection
      │
      ▼
Risk Scoring
```

---

## Technologies Used

* Rust
* Goblin
* Regex
* Base64
* Shannon Entropy

---

## Running

Clone the repository:

```bash
git clone <repository-url>
cd binary_analysis_toolkit/rust_impl
```

Build the project:

```bash
cargo build
```

Run against a binary:

```bash
cargo run -- <path-to-binary>
```

Example:

```bash
cargo run -- samples/pe/pe-sample
```

---

## Current Progress

### Implemented

* Format detection
* Metadata extraction
* Section extraction
* String extraction
* Import extraction
* Suspicious import analysis
* URL detection
* IPv4 detection
* Credential detection
* Base64 detection
* Hex string detection
* High entropy string detection
* Section entropy analysis
* Packed binary detection
* Risk scoring engine

### Planned

* Symbol extraction
* Capstone disassembly
* Instruction-level heuristics
* Anti-debugging detection
* Automated report generation
* Challenge binary support

---

## Design Philosophy

The project emphasizes:

* Modular architecture
* Readable implementation
* Signature-driven heuristics
* Educational value
* Extensibility

Heuristic logic is intentionally separated from heuristic data so that detection rules can evolve independently of the analysis engine.

---

## Disclaimer

This toolkit is intended for **educational purposes only**. It is designed to help students understand executable formats, static analysis techniques, and reverse engineering workflows. It is **not** intended to replace professional malware analysis frameworks or commercial reverse engineering tools.

---

## License

This project is developed as part of an academic cybersecurity project. The licensing terms may be updated as development progresses.
