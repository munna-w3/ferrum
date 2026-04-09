use serde_json::{json, Value};
use crate::lifter::IrProgram;
use crate::detectors::{Finding, Severity};

// ─────────────────────────────────────────────────────────────────────────────
// ANSI helpers
// ─────────────────────────────────────────────────────────────────────────────

const RESET:  &str = "\x1b[0m";
const BOLD:   &str = "\x1b[1m";
const DIM:    &str = "\x1b[2m";
const RED:    &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const BLUE:   &str = "\x1b[34m";
const CYAN:   &str = "\x1b[36m";
const WHITE:  &str = "\x1b[37m";
const BRED:   &str = "\x1b[1;91m"; // bold bright-red

fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => BRED,
        Severity::High     => RED,
        Severity::Medium   => YELLOW,
        Severity::Low      => BLUE,
        Severity::Info     => WHITE,
    }
}

struct Pen {
    color: bool,
}

impl Pen {
    fn new(color: bool) -> Self { Pen { color } }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color { format!("{}{}{}", code, text, RESET) } else { text.to_string() }
    }

    fn bold(&self, t: &str)  -> String { self.paint(BOLD, t) }
    fn dim(&self,  t: &str)  -> String { self.paint(DIM,  t) }
    fn cyan(&self, t: &str)  -> String { self.paint(CYAN, t) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Text output
// ─────────────────────────────────────────────────────────────────────────────

pub fn format_text(prog: &IrProgram, findings: &[Finding], color: bool) -> String {
    let p  = Pen::new(color);
    let hr = "─".repeat(40);
    let eq = "═".repeat(60);
    let mut out = String::new();

    // ── Banner ────────────────────────────────────────────────────────────
    out += &p.bold(&eq); out += "\n";
    out += &p.bold("  FERRUM  ·  EVM Security Analyzer  ·  Rust Edition"); out += "\n";
    out += &p.bold(&eq); out += "\n\n";

    // ── Stats ─────────────────────────────────────────────────────────────
    out += &format!("  {}  {}\n",
        p.bold("Bytecode  :"),
        format!("{} bytes  ·  {} opcodes  ·  {} blocks",
            prog.bytecode_len, prog.insn_count(), prog.blocks.len()));

    // ── Functions ─────────────────────────────────────────────────────────
    out += &format!("\n  {}\n", p.bold("Identified Functions"));
    out += &format!("  {}\n", p.dim(&hr));

    if prog.functions.is_empty() {
        out += &format!("  {}\n", p.dim("(none detected — bytecode may be a constructor or minimal proxy)"));
    } else {
        for f in &prog.functions {
            let sel = f.selector
                .map(|s| format!(" {}", p.dim(&format!("[{:#010x}]", s))))
                .unwrap_or_default();
            out += &format!("  {:#06x}  {}{}\n", f.offset, p.cyan(&f.name), sel);
        }
    }

    // ── Storage slots ────────────────────────────────────────────────────
    let slots = prog.sstore_slots();
    if !slots.is_empty() {
        let slot_list: Vec<String> = slots.iter().map(|w| format!("{}", w)).collect();
        out += &format!("\n  {}  {}\n",
            p.bold("Storage slots :"),
            slot_list.join(", "));
    }

    // ── Ether ────────────────────────────────────────────────────────────
    out += &format!("  {}  {}\n",
        p.bold("Sends ether   :"),
        if prog.can_send_ether() { p.paint(YELLOW, "yes") } else { "no".into() });

    // ── Findings ─────────────────────────────────────────────────────────
    out += &format!("\n  {}\n", p.bold("Security Findings"));
    out += &format!("  {}\n", p.dim(&hr));

    if findings.is_empty() {
        out += &format!("  {}\n", p.dim("No issues detected."));
    } else {
        for (i, f) in findings.iter().enumerate() {
            // Index + severity
            out += &format!("\n  {}  {}  ·  {}\n",
                p.bold(&format!("[{}]", i + 1)),
                p.paint(sev_color(f.severity), &format!("{:<8}", f.severity.label())),
                p.bold(f.title));

            // Location
            let loc = match (&f.function_name, f.pc) {
                (Some(n), Some(pc)) => format!("{} @ {:#x}", n, pc),
                (None,    Some(pc)) => format!("{:#x}", pc),
                (Some(n), None)     => n.clone(),
                (None,    None)     => String::from("unknown"),
            };
            out += &format!("       {}\n", p.dim(&loc));

            // Description (word-wrap at ~72 chars)
            for line in wrap(&f.description, 70) {
                out += &format!("       {}\n", line);
            }
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────
    out += "\n";
    out += &p.bold(&eq); out += "\n";

    let counts: Vec<String> = [
        Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info,
    ].iter().map(|&s| {
        let n = findings.iter().filter(|f| f.severity == s).count();
        let label = format!("{} {}", s.label(), n);
        if n > 0 { p.paint(sev_color(s), &label) } else { p.dim(&label) }
    }).collect();

    out += &format!("  {}\n", counts.join("  ·  "));
    out += &p.bold(&eq); out += "\n";

    out
}

/// Naive word-wrapper.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if !cur.is_empty() && cur.len() + 1 + word.len() > width {
            lines.push(cur.clone());
            cur.clear();
        }
        if !cur.is_empty() { cur.push(' '); }
        cur.push_str(word);
    }
    if !cur.is_empty() { lines.push(cur); }
    lines
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON output
// ─────────────────────────────────────────────────────────────────────────────

pub fn format_json(prog: &IrProgram, findings: &[Finding]) -> String {
    let functions: Vec<Value> = prog.functions.iter().map(|f| {
        json!({
            "offset":   format!("{:#x}", f.offset),
            "name":     f.name,
            "selector": f.selector.map(|s| format!("{:#010x}", s)),
        })
    }).collect();

    let slots: Vec<String> = prog.sstore_slots().iter().map(|w| format!("{}", w)).collect();

    let summary = {
        let mut m = serde_json::Map::new();
        for s in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info] {
            let n = findings.iter().filter(|f| f.severity == s).count();
            m.insert(s.label().to_lowercase(), json!(n));
        }
        Value::Object(m)
    };

    let findings_json: Vec<Value> = findings.iter().map(|f| {
        json!({
            "severity":      f.severity.label(),
            "id":            f.id,
            "title":         f.title,
            "description":   f.description,
            "pc":            f.pc.map(|p| format!("{:#x}", p)),
            "function":      f.function_name,
        })
    }).collect();

    let root = json!({
        "bytecode_bytes": prog.bytecode_len,
        "opcodes":        prog.insn_count(),
        "blocks":         prog.blocks.len(),
        "functions":      functions,
        "storage_slots":  slots,
        "can_send_ether": prog.can_send_ether(),
        "findings":       findings_json,
        "summary":        summary,
    });

    serde_json::to_string_pretty(&root).unwrap_or_default()
}

// ─────────────────────────────────────────────────────────────────────────────
// SARIF 2.1.0 output  (GitHub Code Scanning / CI integration)
// ─────────────────────────────────────────────────────────────────────────────

pub fn format_sarif(prog: &IrProgram, findings: &[Finding]) -> String {
    use crate::detectors::list_all_detectors;

    // Build the rules array from detector metadata
    let rules: Vec<Value> = list_all_detectors().iter().map(|d| {
        json!({
            "id":   d.id,
            "name": d.title.replace(' ', ""),
            "shortDescription": { "text": d.title },
            "fullDescription":  { "text": d.description },
            "helpUri": d.swc.map(|s| {
                format!("https://swcregistry.io/docs/{}", s)
            }),
            "properties": {
                "severity": d.severity.label(),
                "swc":      d.swc,
            },
            "defaultConfiguration": {
                "level": d.severity.sarif_level(),
            },
        })
    }).collect();

    // One SARIF result per finding
    let results: Vec<Value> = findings.iter().map(|f| {
        let location = if let Some(pc) = f.pc {
            json!([{
                "physicalLocation": {
                    "address": {
                        "absoluteAddress": pc,
                        "offsetFromContextRegionStartAddress": 0,
                    }
                },
                "logicalLocations": f.function_name.as_ref().map(|n| {
                    json!([{ "name": n, "kind": "function" }])
                }),
            }])
        } else {
            json!([])
        };

        json!({
            "ruleId":   f.id,
            "level":    f.severity.sarif_level(),
            "message":  { "text": f.description },
            "locations": location,
        })
    }).collect();

    let root = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name":           "ferrum",
                    "version":        "0.2.0",
                    "informationUri": "https://github.com/m3h3d1/ferrum",
                    "rules":          rules,
                }
            },
            "properties": {
                "bytecode_bytes": prog.bytecode_len,
                "opcodes":        prog.insn_count(),
                "blocks":         prog.blocks.len(),
            },
            "results": results,
        }]
    });

    serde_json::to_string_pretty(&root).unwrap_or_default()
}
