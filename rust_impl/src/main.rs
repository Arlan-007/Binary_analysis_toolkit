use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use rust_impl::analysis::heuristics::{
    detect_encoded_strings, detect_packed_binary, high_entropy_sections, high_entropy_strings,
    suspicious_credentials, suspicious_imports, suspicious_ip, suspicious_sections, suspicious_url,
};
use rust_impl::analysis::import::{get_imports, get_needed_libraries};
use rust_impl::analysis::risk::calculate_risk_score;
use rust_impl::analysis::string::extract_strings;
use rust_impl::analysis::symbol::{get_exports, get_symbols};
use rust_impl::disarm::{
    DisassemblyError, DisassemblyOptions, SymbolLabels, analyze_instructions, build_symbol_labels,
    disassemble_at, disassemble_from_entrypoint, disassemble_text, extract_code_features,
    symbol_address,
};
use rust_impl::format::detect::detect_format;
use rust_impl::format::elf::get_elf_metadata;
use rust_impl::format::pe::get_pe_metadata;
use rust_impl::models::{BinaryFormat, BinaryInfo, CodeFeatures, Disassembly, Finding};
use rust_impl::report::{CodeScan, ReportInput, render_report};

const CODE_SCAN_MAX_BYTES: usize = 1_048_576;
const CODE_SCAN_MAX_INSTRUCTIONS: usize = 100_000;
const REPORT_DIRECTORY: &str = "report";

#[derive(Debug, Parser)]
#[command(about = "Static binary-analysis toolkit with bounded Capstone disassembly")]
struct Cli {
    /// Path to the binary to analyze.
    binary: PathBuf,

    /// Optional disassembly target. Omit this to show analysis without an instruction listing.
    #[arg(long, value_enum)]
    disasm: Option<DisassemblyTarget>,

    /// Starting address for `--disasm address` (decimal or 0x-prefixed hexadecimal).
    #[arg(long, value_parser = parse_address)]
    address: Option<u64>,

    /// Exact symbol/export name for `--disasm symbol`.
    #[arg(long)]
    symbol: Option<String>,

    /// Maximum number of bytes shown by an explicit disassembly request.
    #[arg(long, default_value_t = 4096)]
    max_bytes: usize,

    /// Maximum number of instructions shown by an explicit disassembly request.
    #[arg(long, default_value_t = 200)]
    max_instructions: usize,

    /// Where to write the Markdown report. Defaults to `report/<binary>.report.md`.
    #[arg(long)]
    report: Option<PathBuf>,
}

struct CodeScanResult {
    findings: Vec<Finding>,
    features: CodeFeatures,
    disassembly: Disassembly,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DisassemblyTarget {
    Text,
    Entrypoint,
    Address,
    Symbol,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    validate_cli(&cli)?;

    let path = cli.binary.to_string_lossy();
    let file_size = std::fs::metadata(&cli.binary)?.len();
    let format = detect_format(&path)?;
    let info = match format {
        BinaryFormat::Elf => get_elf_metadata(&path)?,
        BinaryFormat::Pe => get_pe_metadata(&path)?,
        BinaryFormat::MachO => return Err("Mach-O analysis is not implemented".into()),
        BinaryFormat::Unknown => return Err("unknown binary format".into()),
    };

    let strings = extract_strings(&path)?;
    let imports = get_imports(&path, format)?;
    let needed_libraries = get_needed_libraries(&path, format)?;
    let exports = get_exports(&path, format)?;
    let symbols = get_symbols(&path, format)?;
    let labels = build_symbol_labels(&symbols, &exports);

    println!("Format: {:?}", info.format);
    println!("Architecture: {}", info.architecture);
    println!("Entrypoint: 0x{:x}", info.entrypoint);
    println!("Found {} strings", strings.len());
    println!("Found {} imports", imports.len());
    println!("Found {} needed libraries", needed_libraries.len());
    for library in &needed_libraries {
        println!("  needs {library}");
    }
    println!("Found {} exports", exports.len());
    println!("Found {} symbols", symbols.len());

    let suspicious_imports = suspicious_imports(&imports);
    let suspicious_url = suspicious_url(&strings);
    let suspicious_ip = suspicious_ip(&strings);
    let credentials = suspicious_credentials(&strings);
    let suspicious_sections = suspicious_sections(&info.sections);
    let encodings = detect_encoded_strings(&strings);
    let entropy_string = high_entropy_strings(&strings);
    let entropy_section = high_entropy_sections(&info.sections);
    let is_stripped = match format {
        BinaryFormat::Elf => Some(symbols.is_empty()),
        BinaryFormat::Pe | BinaryFormat::MachO | BinaryFormat::Unknown => None,
    };
    let packed_binary = detect_packed_binary(&info.sections, is_stripped.unwrap_or(false));

    let mut all_findings = Vec::new();
    all_findings.extend(suspicious_imports);
    all_findings.extend(suspicious_url);
    all_findings.extend(suspicious_ip);
    all_findings.extend(credentials);
    all_findings.extend(suspicious_sections);
    all_findings.extend(encodings);
    all_findings.extend(entropy_string);
    all_findings.extend(entropy_section);
    all_findings.extend(packed_binary);

    let code_scan = match scan_code(&info, &labels)? {
        Some(mut scan) => {
            print_code_features(&scan.features);
            all_findings.append(&mut scan.findings);
            Some(scan)
        }
        None => None,
    };

    if let Some(target) = cli.disasm {
        let options = DisassemblyOptions {
            max_bytes: cli.max_bytes,
            max_instructions: cli.max_instructions,
        };
        let disassembly = select_disassembly(&info, &labels, target, &cli, options)?;
        print_disassembly(&disassembly, &labels);
    }

    let risk = calculate_risk_score(&all_findings);
    print_findings(&all_findings);
    println!("Risk summary: {risk:#?}");

    let code = code_scan.as_ref().map(|scan| CodeScan {
        disassembly: &scan.disassembly,
        features: &scan.features,
        instruction_budget: CODE_SCAN_MAX_INSTRUCTIONS,
    });
    let input = ReportInput {
        path: &path,
        file_size,
        is_stripped,
    };
    let report = render_report(&input, &info, &all_findings, &risk, code.as_ref());

    write_report(&cli, &report)?;

    Ok(())
}

fn write_report(cli: &Cli, report: &str) -> Result<(), Box<dyn Error>> {
    let destination = match &cli.report {
        Some(destination) => destination.clone(),
        None => {
            std::fs::create_dir_all(REPORT_DIRECTORY)?;
            Path::new(REPORT_DIRECTORY).join(report_file_name(&cli.binary))
        }
    };

    if destination.is_dir() {
        return Err(format!(
            "report destination '{}' is a directory; specify a file path instead",
            destination.display()
        )
        .into());
    }

    std::fs::write(&destination, report)?;
    println!("Report written to {}", destination.display());
    Ok(())
}

fn report_file_name(binary: &Path) -> OsString {
    let path_str = binary.to_string_lossy();
    let mut hash: u64 = 14_695_981_039_346_656_037;
    for byte in path_str.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(1_099_511_628_211);
    }

    let mut name = binary
        .file_name()
        .unwrap_or_else(|| OsStr::new("binary"))
        .to_os_string();
    name.push(format!("-{:08x}", hash as u32));
    name.push(".report.md");
    name
}

fn validate_cli(cli: &Cli) -> Result<(), DisassemblyError> {
    if cli.max_bytes == 0 || cli.max_instructions == 0 {
        return Err(DisassemblyError::InvalidRequest(
            "--max-bytes and --max-instructions must be greater than zero".to_string(),
        ));
    }

    match cli.disasm {
        None if cli.address.is_some() || cli.symbol.is_some() => {
            Err(DisassemblyError::InvalidRequest(
                "--address and --symbol require a corresponding --disasm target".to_string(),
            ))
        }
        Some(DisassemblyTarget::Text | DisassemblyTarget::Entrypoint)
            if cli.address.is_some() || cli.symbol.is_some() =>
        {
            Err(DisassemblyError::InvalidRequest(
                "--address and --symbol do not apply to this disassembly target".to_string(),
            ))
        }
        Some(DisassemblyTarget::Address) if cli.address.is_none() => Err(
            DisassemblyError::InvalidRequest("--disasm address requires --address".to_string()),
        ),
        Some(DisassemblyTarget::Address) if cli.symbol.is_some() => {
            Err(DisassemblyError::InvalidRequest(
                "--symbol can only be used with --disasm symbol".to_string(),
            ))
        }
        Some(DisassemblyTarget::Symbol) if cli.symbol.is_none() => Err(
            DisassemblyError::InvalidRequest("--disasm symbol requires --symbol NAME".to_string()),
        ),
        Some(DisassemblyTarget::Symbol) if cli.address.is_some() => {
            Err(DisassemblyError::InvalidRequest(
                "--address can only be used with --disasm address".to_string(),
            ))
        }
        _ => Ok(()),
    }
}

fn scan_code(
    info: &BinaryInfo,
    labels: &SymbolLabels,
) -> Result<Option<CodeScanResult>, DisassemblyError> {
    let options = DisassemblyOptions {
        max_bytes: CODE_SCAN_MAX_BYTES,
        max_instructions: CODE_SCAN_MAX_INSTRUCTIONS,
    };

    match disassemble_text(info, labels, options) {
        Ok(disassembly) => {
            let findings =
                analyze_instructions(info.format, &info.architecture, &disassembly.instructions);
            let features = extract_code_features(&disassembly.instructions, &findings);
            Ok(Some(CodeScanResult {
                findings,
                features,
                disassembly,
            }))
        }
        Err(
            error @ (DisassemblyError::UnsupportedArchitecture(_)
            | DisassemblyError::MissingTextSection
            | DisassemblyError::NoInstructionsDecoded),
        ) => {
            eprintln!("Code scan skipped: {error}");
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn select_disassembly(
    info: &BinaryInfo,
    labels: &SymbolLabels,
    target: DisassemblyTarget,
    cli: &Cli,
    options: DisassemblyOptions,
) -> Result<Disassembly, DisassemblyError> {
    match target {
        DisassemblyTarget::Text => disassemble_text(info, labels, options),
        DisassemblyTarget::Entrypoint => disassemble_from_entrypoint(info, labels, options),
        DisassemblyTarget::Address => {
            let address = cli.address.ok_or_else(|| {
                DisassemblyError::InvalidRequest("--disasm address requires --address".to_string())
            })?;
            disassemble_at(info, address, labels, options)
        }
        DisassemblyTarget::Symbol => {
            let symbol = cli.symbol.as_deref().ok_or_else(|| {
                DisassemblyError::InvalidRequest(
                    "--disasm symbol requires --symbol NAME".to_string(),
                )
            })?;
            let address = symbol_address(labels, symbol)
                .ok_or_else(|| DisassemblyError::MissingSymbol(symbol.to_string()))?;
            disassemble_at(info, address, labels, options)
        }
    }
}

fn print_disassembly(disassembly: &Disassembly, labels: &SymbolLabels) {
    println!(
        "Disassembly: {} from {} 0x{:x} (decoded {} of {} input bytes; {} instructions)",
        disassembly.section_name,
        disassembly.address_kind.short_name(),
        disassembly.start_address,
        disassembly.decoded_byte_count,
        disassembly.input_byte_count,
        disassembly.instructions.len(),
    );
    for instruction in &disassembly.instructions {
        if let Some(label) = &instruction.symbol_label {
            println!("{label}:");
        }
        let bytes = instruction
            .bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let target = instruction
            .branch_target
            .map(|address| branch_annotation(address, labels))
            .unwrap_or_default();
        println!(
            "  {} 0x{:016x}  {:<24} {:<10} {}{}",
            disassembly.address_kind.short_name(),
            instruction.address,
            bytes,
            instruction.mnemonic,
            instruction.operands,
            target,
        );
    }
}

fn branch_annotation(address: u64, labels: &SymbolLabels) -> String {
    match labels.get(&address) {
        Some(names) => format!("    ; -> {}", names.join(" | ")),
        None => format!("    ; -> 0x{address:x}"),
    }
}

fn print_code_features(features: &CodeFeatures) {
    println!(
        "Code features: instructions={} calls={} branches={} returns={} syscalls={} traps={} timing={} anti_debug={}",
        features.instruction_count,
        features.call_count,
        features.branch_count,
        features.return_count,
        features.syscall_count,
        features.trap_count,
        features.timing_instruction_count,
        features.anti_debug_pattern_count,
    );
}

fn print_findings(findings: &[Finding]) {
    println!("Findings: {}", findings.len());
    for finding in findings {
        println!(
            "  [{:?}] {} / {} — {}",
            finding.severity, finding.category, finding.title, finding.description
        );
    }
}

fn parse_address(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    let hexadecimal = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"));
    match hexadecimal {
        Some(value) => u64::from_str_radix(value, 16).map_err(|error| error.to_string()),
        None => trimmed.parse::<u64>().map_err(|error| error.to_string()),
    }
}
