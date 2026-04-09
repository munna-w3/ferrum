use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process;

use clap::Parser;

use ferrum::{cfg, detectors, disasm, lifter, output, taint};

#[derive(Parser, Debug)]
#[command(
    name    = "ferrum",
    version = "0.2.0",
    about   = "EVM bytecode security analyzer — fast, dependency-free, Rust-native",
    long_about = "Disassembles EVM bytecode, lifts it to an SSA-like IR, runs forward taint\n\
                  analysis, and applies 10 vulnerability detectors covering the most critical\n\
                  SWC registry entries.\n\n\
                  INPUT  hex-encoded or raw EVM bytecode from a FILE or stdin.\n\
                  Accepts '0x'-prefixed hex, bare hex, or raw binary.\n\n\
                  EXAMPLES\n  \
                    ferrum -i contract.bin\n  \
                    echo '6080604052...' | ferrum\n  \
                    ferrum -i contract.bin --json -o report.json\n  \
                    ferrum -i contract.bin --sarif > results.sarif\n  \
                    ferrum --list-detectors"
)]
struct Args {
    /// Input file containing EVM bytecode (hex or raw binary).
    /// Reads from stdin when omitted.
    #[arg(short, long, value_name = "FILE")]
    input: Option<PathBuf>,

    /// Emit results as JSON (structured, machine-readable).
    #[arg(short, long)]
    json: bool,

    /// Emit results in SARIF 2.1.0 format (GitHub Code Scanning / CI integration).
    #[arg(long)]
    sarif: bool,

    /// Force ANSI colored output even when stdout is not a TTY.
    #[arg(long)]
    color: bool,

    /// Suppress ANSI color codes.
    #[arg(long)]
    no_color: bool,

    /// Write output to FILE instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Print disassembled instructions (PC  OPCODE  [immediate]) and exit.
    #[arg(long)]
    disasm: bool,

    /// Print all available detectors with severity, SWC ID, and description, then exit.
    #[arg(long)]
    list_detectors: bool,
}

fn main() {
    let args = Args::parse();

    // ── List-detectors mode ───────────────────────────────────────────────
    if args.list_detectors {
        let det = detectors::list_all_detectors();
        println!("{:<32} {:<10} {:<12} {}", "ID", "SEVERITY", "SWC", "TITLE");
        println!("{}", "─".repeat(78));
        for d in &det {
            println!("{:<32} {:<10} {:<12} {}",
                d.id, d.severity.label(), d.swc.unwrap_or("—"), d.title);
        }
        println!("\n{} detectors total.", det.len());
        return;
    }

    // ── Read input ────────────────────────────────────────────────────────
    let raw: Vec<u8> = if let Some(ref path) = args.input {
        fs::read(path).unwrap_or_else(|e| {
            eprintln!("ferrum: cannot read '{}': {}", path.display(), e);
            process::exit(1);
        })
    } else {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).unwrap_or_else(|e| {
            eprintln!("ferrum: stdin read error: {}", e);
            process::exit(1);
        });
        buf
    };

    if raw.is_empty() {
        eprintln!("ferrum: empty input — provide a bytecode file with -i or pipe via stdin");
        process::exit(1);
    }

    let bytecode = disasm::parse_input(&raw);

    // ── Disasm-only mode ──────────────────────────────────────────────────
    if args.disasm {
        let insns = disasm::disassemble(&bytecode);
        for ins in &insns {
            let imm = if ins.imm.is_empty() {
                String::new()
            } else {
                let hex: String = ins.imm.iter().map(|b| format!("{:02x}", b)).collect();
                format!(" 0x{}", hex)
            };
            println!("{:#06x}  {}{}", ins.pc, ins.op.name(), imm);
        }
        return;
    }

    // ── Full analysis pipeline ────────────────────────────────────────────
    let insns    = disasm::disassemble(&bytecode);
    let cfg      = cfg::build_cfg(&insns);
    let prog     = lifter::lift(&insns, &cfg);
    let taint    = taint::analyze(&prog);
    let findings = detectors::run_all(&prog, &taint);

    // ── Colour decision ───────────────────────────────────────────────────
    let use_color = if args.no_color || args.json || args.sarif {
        false
    } else if args.color {
        true
    } else {
        io::stdout().is_terminal() && args.output.is_none()
    };

    // ── Format ────────────────────────────────────────────────────────────
    let text = if args.sarif {
        output::format_sarif(&prog, &findings)
    } else if args.json {
        output::format_json(&prog, &findings)
    } else {
        output::format_text(&prog, &findings, use_color)
    };

    // ── Write ─────────────────────────────────────────────────────────────
    if let Some(ref path) = args.output {
        fs::write(path, &text).unwrap_or_else(|e| {
            eprintln!("ferrum: cannot write '{}': {}", path.display(), e);
            process::exit(1);
        });
        eprintln!("ferrum: report written to {}", path.display());
    } else {
        print!("{}", text);
    }

    // Non-zero exit when any Critical or High finding exists (useful for CI gates)
    let bad = findings.iter().any(|f| {
        matches!(f.severity, detectors::Severity::Critical | detectors::Severity::High)
    });
    process::exit(if bad { 1 } else { 0 });
}
