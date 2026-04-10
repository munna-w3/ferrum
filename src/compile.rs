use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

pub struct CompiledContract {
    pub name:     String,
    pub bytecode: Vec<u8>,
    /// Runtime source map from solc (empty when not available).
    pub src_map:  String,
    /// Full source file content (empty when not available).
    pub source:   String,
    /// 4-byte selector → plain function name (e.g. `0xa9059cbb → "transfer"`).
    pub fn_names: HashMap<u32, String>,
}

/// Compile a `.sol` file with `solc` and return each deployable contract's
/// runtime bytecode plus its source map and ABI selector hashes.
/// Interfaces and abstract contracts (empty bin-runtime) are silently skipped.
pub fn compile_sol(path: &Path) -> Result<Vec<CompiledContract>, String> {
    if Command::new("solc").arg("--version").output().is_err() {
        return Err(
            "solc not found in PATH.\n\
             Install it from https://docs.soliditylang.org/en/latest/installing-solidity.html\n\
             or via a package manager (e.g. `brew install solidity`)."
                .to_string(),
        );
    }

    let dir = path.parent().unwrap_or(Path::new("."));

    let out = Command::new("solc")
        .arg("--combined-json")
        .arg("bin-runtime,srcmap-runtime,hashes")
        .arg("--allow-paths")
        .arg(dir)
        .arg(path)
        .output()
        .map_err(|e| format!("failed to spawn solc: {}", e))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("solc compilation failed:\n{}", stderr.trim()));
    }

    let source = std::fs::read_to_string(path).unwrap_or_default();
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_combined_json(&stdout, source)
}

fn parse_combined_json(json: &str, source: String) -> Result<Vec<CompiledContract>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("failed to parse solc output: {}", e))?;

    let contracts = v
        .get("contracts")
        .and_then(|c| c.as_object())
        .ok_or_else(|| "solc output missing 'contracts' field".to_string())?;

    let mut result = Vec::new();
    for (key, contract) in contracts {
        let bin_runtime = contract
            .get("bin-runtime")
            .and_then(|b| b.as_str())
            .unwrap_or("");

        if bin_runtime.is_empty() {
            continue;
        }

        let bytecode = crate::disasm::decode_hex_str(bin_runtime)
            .ok_or_else(|| format!("invalid hex bytecode for '{}'", key))?;

        let src_map = contract
            .get("srcmap-runtime")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();

        let fn_names = contract
            .get("hashes")
            .map(parse_hashes)
            .unwrap_or_default();

        let name = key.rsplit(':').next().unwrap_or(key).to_string();
        result.push(CompiledContract { name, bytecode, src_map, source: source.clone(), fn_names });
    }

    if result.is_empty() {
        return Err(
            "no deployable contracts found — interfaces and abstract contracts are skipped"
                .to_string(),
        );
    }

    Ok(result)
}

/// Parse `solc`'s `hashes` object (`{"transfer(address,uint256)": "a9059cbb", …}`)
/// into a map of 4-byte selector → bare function name.
fn parse_hashes(val: &serde_json::Value) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if let Some(obj) = val.as_object() {
        for (sig, sel_val) in obj {
            if let Some(sel_str) = sel_val.as_str() {
                let hex = sel_str.trim_start_matches("0x");
                if let Ok(sel) = u32::from_str_radix(hex, 16) {
                    let name = sig.split('(').next().unwrap_or(sig).to_string();
                    map.insert(sel, name);
                }
            }
        }
    }
    map
}

// ── Source-map helpers ────────────────────────────────────────────────────────

/// Map a bytecode `pc` to `(line_number, trimmed_line_text)` using
/// `solc`'s runtime source map and the original source.
///
/// Returns `None` when the PC has no meaningful source mapping (compiler-
/// generated stubs, metadata, out-of-range entries, etc.).
pub fn pc_to_source_line(
    src_map: &str,
    raw_insns: &[crate::disasm::RawInsn],
    source: &str,
    pc: usize,
) -> Option<(usize, String)> {
    if src_map.is_empty() || source.is_empty() { return None; }

    let idx = raw_insns.iter().position(|ins| ins.pc == pc)?;
    let (s, _l, f) = src_entry_at(src_map, idx)?;

    // f == -1 means compiler-generated; skip those entries
    if s < 0 || f != 0 { return None; }

    offset_to_line(source, s as usize)
}

/// Walk the compressed source map and return `(s, l, f)` for entry `idx`.
///
/// Format: `s:l:f:j;s:l:f:j;…`  — missing fields inherit from the previous
/// entry (Solidity source-map compression spec).
fn src_entry_at(src_map: &str, idx: usize) -> Option<(i32, i32, i32)> {
    let mut s: i32 = -1;
    let mut l: i32 =  0;
    let mut f: i32 = -1;

    for (i, entry) in src_map.split(';').enumerate() {
        let parts: Vec<&str> = entry.split(':').collect();
        if let Some(p) = parts.first()  { if !p.is_empty() { s = p.parse().unwrap_or(s); } }
        if let Some(p) = parts.get(1)   { if !p.is_empty() { l = p.parse().unwrap_or(l); } }
        if let Some(p) = parts.get(2)   { if !p.is_empty() { f = p.parse().unwrap_or(f); } }
        if i == idx { return Some((s, l, f)); }
    }
    None
}

/// Convert a byte offset inside `source` to `(1-based line number, trimmed line text)`.
fn offset_to_line(source: &str, offset: usize) -> Option<(usize, String)> {
    if offset >= source.len() { return None; }

    let mut line_num   = 1usize;
    let mut line_start = 0usize;

    for (i, c) in source.char_indices() {
        if i >= offset { break; }
        if c == '\n' {
            line_num  += 1;
            line_start = i + 1;
        }
    }

    let rest = &source[line_start..];
    let line_end = rest.find('\n').unwrap_or(rest.len());
    let line = rest[..line_end].trim().to_string();

    if line.is_empty() { None } else { Some((line_num, line)) }
}

/// Scan backward from `line_number` (1-based) through `source` to find the
/// nearest enclosing Solidity function declaration and return its name.
///
/// Matches lines that contain `function <ident>(` — simple text scan,
/// good enough for security analysis without a full parser.
pub fn enclosing_function_name(source: &str, line_number: usize) -> Option<String> {
    // Collect lines up to line_number, then scan backward.
    let lines: Vec<&str> = source.lines().take(line_number).collect();
    for line in lines.iter().rev() {
        let trimmed = line.trim();
        // Find `function ` keyword (may be preceded by visibility etc.)
        if let Some(pos) = trimmed.find("function ") {
            let after = &trimmed[pos + "function ".len()..].trim_start();
            if let Some(paren) = after.find('(') {
                let name = after[..paren].trim();
                // Must look like a valid identifier
                if !name.is_empty()
                    && name.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}
