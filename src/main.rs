use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;
use std::process;

use clap::Parser;
use serde_json::Value;

use ferrum::{cfg, compile, detectors, disasm, lifter, output, taint};
use ferrum::detectors::{Finding, Severity};
use ferrum::lifter::IrProgram;

#[derive(Parser, Debug)]
#[command(
    name    = "ferrum",
    version = "0.2.0",
    about   = "EVM bytecode security analyzer — fast, dependency-free, Rust-native",
    long_about = "Disassembles EVM bytecode, lifts it to an SSA-like IR, runs forward taint\n\
                  analysis, and applies 10 vulnerability detectors covering the most critical\n\
                  SWC registry entries.\n\n\
                  INPUT  a Solidity source file (.sol), hex-encoded bytecode, or raw binary,\n\
                  from a FILE or stdin. Solidity files are compiled on-the-fly via solc.\n\
                  Accepts '0x'-prefixed hex, bare hex, or raw binary.\n\n\
                  EXAMPLES\n  \
                    ferrum -i contract.sol\n  \
                    ferrum -i contract.bin\n  \
                    echo '6080604052...' | ferrum\n  \
                    ferrum -i contract.sol --json -o report.json\n  \
                    ferrum -i contract.sol --sarif > results.sarif\n  \
                    ferrum --list-detectors"
)]
struct Args {
    /// Input file: a .sol source file or a file containing EVM bytecode (hex or raw binary).
    /// Reads bytecode from stdin when omitted.
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

    // ── Colour decision (computed before branching) ───────────────────────
    let use_color = if args.no_color || args.json || args.sarif {
        false
    } else if args.color {
        true
    } else {
        io::stdout().is_terminal() && args.output.is_none()
    };

    // ── Route: .sol source vs pre-compiled bytecode ───────────────────────
    let is_sol = args.input.as_ref()
        .map(|p| p.extension().map(|e| e.eq_ignore_ascii_case("sol")).unwrap_or(false))
        .unwrap_or(false);

    if is_sol {
        run_sol(&args, use_color);
    } else {
        run_bytecode(&args, use_color);
    }
}

// ── Solidity source path ──────────────────────────────────────────────────────

fn run_sol(args: &Args, use_color: bool) {
    let path = args.input.as_ref().unwrap();

    let contracts = compile::compile_sol(path).unwrap_or_else(|e| {
        eprintln!("ferrum: {}", e);
        process::exit(1);
    });

    let mut any_bad = false;

    let text = if args.json {
        // Produce a JSON array; each element gets a leading "contract" key.
        let items: Vec<Value> = contracts.iter().map(|c| {
            let (prog, findings) = pipeline(&c.bytecode);
            any_bad = any_bad || is_bad(&findings);
            let raw = output::format_json(&prog, &findings);
            let mut obj: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            if let Some(map) = obj.as_object_mut() {
                map.insert("contract".to_string(), Value::String(c.name.clone()));
            }
            obj
        }).collect();

        // Single contract → bare object; multiple → array.
        let root = if items.len() == 1 {
            items.into_iter().next().unwrap()
        } else {
            Value::Array(items)
        };
        serde_json::to_string_pretty(&root).unwrap_or_default()

    } else if args.sarif {
        // Produce a SARIF document; multiple contracts → multiple runs.
        let mut runs: Vec<Value> = Vec::new();
        for c in &contracts {
            let (prog, findings) = pipeline(&c.bytecode);
            any_bad = any_bad || is_bad(&findings);
            let raw = output::format_sarif(&prog, &findings);
            if let Ok(mut sarif) = serde_json::from_str::<Value>(&raw) {
                if let Some(arr) = sarif["runs"].as_array_mut() {
                    for run in arr.iter_mut() {
                        run["properties"]["contract"] = Value::String(c.name.clone());
                    }
                    runs.extend(arr.drain(..));
                }
            }
        }
        let doc = serde_json::json!({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": runs,
        });
        serde_json::to_string_pretty(&doc).unwrap_or_default()

    } else {
        // Text: one section per contract, separated by a header.
        let mut out = String::new();
        for (i, c) in contracts.iter().enumerate() {
            if i > 0 { out.push('\n'); }
            let (prog, findings) = pipeline(&c.bytecode);
            any_bad = any_bad || is_bad(&findings);
            out.push_str(&contract_header(&c.name, use_color));
            out.push_str(&output::format_text(&prog, &findings, use_color));
        }
        out
    };

    write_output(&text, args);
    process::exit(if any_bad { 1 } else { 0 });
}

// ── Pre-compiled bytecode path ────────────────────────────────────────────────

fn run_bytecode(args: &Args, use_color: bool) {
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
        eprintln!("ferrum: empty input — provide a .sol or bytecode file with -i, or pipe via stdin");
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

    let (prog, findings) = pipeline(&bytecode);

    let text = if args.sarif {
        output::format_sarif(&prog, &findings)
    } else if args.json {
        output::format_json(&prog, &findings)
    } else {
        output::format_text(&prog, &findings, use_color)
    };

    write_output(&text, args);

    let bad = is_bad(&findings);
    process::exit(if bad { 1 } else { 0 });
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn pipeline(bytecode: &[u8]) -> (IrProgram, Vec<Finding>) {
    let insns    = disasm::disassemble(bytecode);
    let cfg      = cfg::build_cfg(&insns);
    let prog     = lifter::lift(&insns, &cfg);
    let taint    = taint::analyze(&prog);
    let findings = detectors::run_all(&prog, &taint);
    (prog, findings)
}

fn is_bad(findings: &[Finding]) -> bool {
    findings.iter().any(|f| matches!(f.severity, Severity::Critical | Severity::High))
}

fn contract_header(name: &str, color: bool) -> String {
    let bar = "▌".repeat(3);
    if color {
        format!("\x1b[1;36m{} {}{}\x1b[0m\n\n", bar, name, bar)
    } else {
        format!("=== {} ===\n\n", name)
    }
}

fn write_output(text: &str, args: &Args) {
    if let Some(ref path) = args.output {
        fs::write(path, text).unwrap_or_else(|e| {
            eprintln!("ferrum: cannot write '{}': {}", path.display(), e);
            process::exit(1);
        });
        eprintln!("ferrum: report written to {}", path.display());
    } else {
        print!("{}", text);
    }
}
