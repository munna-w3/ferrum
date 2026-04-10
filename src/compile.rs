use std::path::Path;
use std::process::Command;

pub struct CompiledContract {
    pub name:     String,
    pub bytecode: Vec<u8>,
}

/// Compile a `.sol` file with `solc` and return each deployable contract's
/// runtime bytecode.  Interfaces and abstract contracts (empty bin-runtime)
/// are silently skipped.
pub fn compile_sol(path: &Path) -> Result<Vec<CompiledContract>, String> {
    // Check that solc is on PATH before attempting anything else.
    if Command::new("solc").arg("--version").output().is_err() {
        return Err(
            "solc not found in PATH.\n\
             Install it from https://docs.soliditylang.org/en/latest/installing-solidity.html\n\
             or via a package manager (e.g. `brew install solidity`)."
                .to_string(),
        );
    }

    // Use the file's directory as the base path so relative imports resolve.
    let dir = path.parent().unwrap_or(Path::new("."));

    let out = Command::new("solc")
        .arg("--combined-json")
        .arg("bin-runtime")
        .arg("--allow-paths")
        .arg(dir)
        .arg(path)
        .output()
        .map_err(|e| format!("failed to spawn solc: {}", e))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("solc compilation failed:\n{}", stderr.trim()));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_combined_json(&stdout)
}

fn parse_combined_json(json: &str) -> Result<Vec<CompiledContract>, String> {
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
            // Interface or abstract contract — no runtime code to analyse.
            continue;
        }

        let bytecode = crate::disasm::decode_hex_str(bin_runtime)
            .ok_or_else(|| format!("invalid hex bytecode for '{}'", key))?;

        // Key format is "path/file.sol:ContractName" — take the part after the last ':'.
        let name = key.rsplit(':').next().unwrap_or(key).to_string();
        result.push(CompiledContract { name, bytecode });
    }

    if result.is_empty() {
        return Err(
            "no deployable contracts found — interfaces and abstract contracts are skipped"
                .to_string(),
        );
    }

    Ok(result)
}
