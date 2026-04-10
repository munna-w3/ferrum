# Ferrum

**EVM smart contract security analyzer — written in Rust.**

Ferrum accepts a Solidity source file (`.sol`) or pre-compiled bytecode, disassembles it, lifts it to an SSA-like intermediate representation, runs forward taint analysis, and reports security vulnerabilities with severity levels, precise locations, and remediation guidance.

When a `.sol` file is provided, findings show the **actual function name** and the **exact buggy source line** — not just a bytecode address. When bytecode is provided directly, the standard 4-byte selector signature is shown instead.

Built as a faster, more capable successor to Python-based tools (Mythril, Rattle) with minimal dependencies and sub-millisecond analysis on bytecode.

---

## What it does

### Analysis pipeline

```
Solidity source (.sol)           pre-compiled bytecode (hex / binary)
        │                                        │
        ▼                                        │
  solc compiler                                  │
  (bin-runtime + srcmap-runtime                  │
   + selector hashes per contract)               │
        │                                        │
        └───────────────────┬────────────────────┘
                            ▼
                      Disassembler       — full EVM opcode set incl. PUSH0,
                                           TLOAD/TSTORE, MCOPY (Cancun)
                            │
                            ▼
                      CFG Builder        — basic block identification,
                                           static jump target resolution
                            │
                            ▼
                      IR Lifter          — stack simulation → SSA-like value graph
                                           ABI function detection from 4-byte
                                           selector dispatch
                            │
                            ▼
                      Taint Analysis     — forward BFS from user-controlled sources
                                           (calldata, msg.sender, msg.value,
                                           tx.origin, block.timestamp, blockhash,
                                           block.number, block.coinbase, prevrandao)
                            │
                            ▼
                      Vulnerability Detectors  (13 detectors, see table below)
                            │
                            ▼
                 ┌──────────┴──────────┐
          .sol input              bytecode input
          · bare fn name          · selector signature
          · source line + code    · bytecode PC only
          · line number
```

### Vulnerability detectors

| ID | Severity | SWC | What it catches |
|----|----------|-----|-----------------|
| `REENTRANCY` | HIGH | SWC-107 | CALL before SSTORE — ETH sent before state update (CEI violation) |
| `UNCHECKED-CALL` | MEDIUM | SWC-104 | `CALL`/`CALLCODE` return value never reaches a branch condition |
| `TX-ORIGIN-AUTH` | HIGH | SWC-115 | `tx.origin` flows into a branch — phishing-exploitable auth |
| `UNPROTECTED-SELFDESTRUCT` | CRITICAL | SWC-106 | `SELFDESTRUCT` with no `msg.sender` access control |
| `SELFDESTRUCT-PRESENT` | LOW | SWC-106 | `SELFDESTRUCT` exists but a caller check was found — verify path |
| `TIMESTAMP-DEPENDENCY` | LOW | SWC-116 | `block.timestamp` flows into a branch — manipulable ±12 s |
| `DELEGATECALL-CONTROLLED` | CRITICAL | SWC-112 | `DELEGATECALL` target derived from calldata |
| `INTEGER-OVERFLOW` | HIGH | SWC-101 | ADD/MUL/EXP on user-controlled operand reaching storage or ETH transfer |
| `INTEGER-UNDERFLOW` | HIGH | SWC-101 | SUB on user-controlled operand reaching storage or ETH transfer |
| `ARBITRARY-JUMP` | CRITICAL | SWC-127 | JUMP/JUMPI destination derived from calldata |
| `CONTROLLED-CALL-TARGET` | HIGH | — | CALL target address derived from calldata |
| `WEAK-RANDOMNESS` | MEDIUM | SWC-120 | Block variables (timestamp, blockhash, coinbase…) used as RNG seed |
| `STORAGE-COLLISION` | HIGH | — | `DELEGATECALL` present and `SSTORE` to a low sequential slot — implementation can corrupt proxy state |

### How it compares to Mythril and Rattle

| Feature | Rattle | Mythril | Ferrum |
|---------|--------|---------|--------|
| Input | bytecode | bytecode | **.sol source or bytecode** |
| Vulnerability detectors | None | ~10 (symbolic) | 12 (taint + CFG) |
| Detection approach | — | Symbolic execution | Taint + static CFG |
| Source line in findings | No | No | **Yes (for .sol input)** |
| Actual function name in findings | No | No | **Yes (for .sol input)** |
| Multi-contract files | No | No | Yes |
| Modern opcodes (PUSH0, TLOAD, MCOPY) | No | Partial | Yes |
| JSON output | No | Yes | Yes |
| SARIF 2.1.0 (GitHub Code Scanning) | No | No | Yes |
| CI exit code on HIGH/CRITICAL | No | No | Yes |
| Python required | Yes | Yes | No — single binary |
| Analysis time | ~1 s | 30–300 s | < 10 ms |

---

## Installation

**Requirements:** Rust 1.70+ (install via `rustup`)

```bash
git clone <this-repo>
cd ferrum
cargo build --release
# binary: ./target/release/ferrum
```

Or install to `~/.cargo/bin`:

```bash
cargo install --path .
```

**For Solidity source file analysis:** `solc` must be in your `PATH`.

```bash
# macOS
brew install solidity

# Linux (via snap)
snap install solc --classic

# or download from https://docs.soliditylang.org/en/latest/installing-solidity.html
```

---

## Usage

```
ferrum [OPTIONS]

Options:
  -i, --input <FILE>      .sol source file or EVM bytecode (hex or raw binary);
                          stdin if omitted (bytecode only)
  -j, --json              Emit results as JSON
      --sarif             Emit results as SARIF 2.1.0 (GitHub Code Scanning)
      --disasm            Print disassembled opcodes and exit (bytecode mode only)
      --list-detectors    Print all detectors with severity/SWC and exit
  -o, --output <FILE>     Write output to FILE instead of stdout
      --color             Force ANSI color even when stdout is not a TTY
      --no-color          Suppress ANSI color codes
  -h, --help              Print help
  -V, --version           Print version
```

### Analyze a Solidity source file

```bash
ferrum -i contract.sol
```

Ferrum detects the `.sol` extension, compiles the file with `solc`, and runs the full analysis pipeline on the runtime bytecode of every deployable contract. For each finding the output includes:

- the **bare function name** (e.g. `withdraw`) — resolved by scanning the Solidity source backward from the buggy line to the nearest `function` declaration
- the **exact source line** that triggered the vulnerability (line number + trimmed code)

Interfaces and abstract contracts are skipped automatically.

### Analyze a file with multiple contracts

```bash
ferrum -i contracts/Token.sol
```

Each contract gets its own labeled section in the output. In JSON mode the result is a single object (one contract) or an array (multiple contracts), each with a `"contract"` field.

### Analyze pre-compiled bytecode

```bash
ferrum -i contract.bin          # raw binary or hex file
echo "6080604052..." | ferrum   # hex via stdin
```

For bytecode input the function name shows the ABI selector signature (e.g. `transfer(address,uint256)`) and no source line is available — only the bytecode PC.

### JSON output for scripting

```bash
ferrum -i contract.sol --json
ferrum -i contract.sol --json -o report.json
```

Each finding in JSON mode includes `"source_line"` (integer, 1-based) and `"source_snippet"` (trimmed line text) when analyzing a `.sol` file:

```json
{
  "severity": "HIGH",
  "id": "REENTRANCY",
  "function": "give_some",
  "pc": "0x134",
  "source_line": 8,
  "source_snippet": "(bool success,) = msg.sender.call{value: amount_to_receive}(\"\");",
  "description": "CALL at 0x134 can reach SSTORE at 0x1fc ..."
}
```

### SARIF for GitHub Code Scanning

```bash
ferrum -i contract.sol --sarif > results.sarif
```

Upload with the `upload-sarif` action:

```yaml
- name: Security scan
  run: ferrum -i src/MyContract.sol --sarif -o ferrum.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ferrum.sarif
```

### List all detectors

```bash
ferrum --list-detectors
```

### Disassembly only (bytecode mode)

```bash
ferrum -i contract.bin --disasm
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No CRITICAL or HIGH findings |
| `1` | At least one CRITICAL or HIGH finding (or I/O error) |

---

## Example output

Running `ferrum -i contracts/sam.sol` on a reentrancy-vulnerable contract
(`contracts/sam.sol` — the `give_some` function sends ETH before updating `balance`):

```
=== Sanam ===

════════════════════════════════════════════════════════════
  FERRUM  ·  EVM Security Analyzer  ·  Rust Edition
════════════════════════════════════════════════════════════

  Bytecode  :  1190 bytes  ·  450 opcodes  ·  85 blocks

  Identified Functions
  ────────────────────────────────────────
  0x0038  fn_0x89fdb7d8() [0x89fdb7d8]
  0x0054  fn_0xe3d670d7() [0xe3d670d7]

  Storage slots :  0x1f6
  Sends ether   :  yes

  Security Findings
  ────────────────────────────────────────

  [1]  HIGH      ·  Potential Reentrancy
       give_some @ 0x134
       Line 8:  (bool success,) = msg.sender.call{value: amount_to_receive}("");
       CALL at 0x134 can reach SSTORE at 0x1fc before state is updated. A
       re-entrant attacker can invoke this contract again during the external
       call and observe stale storage values. Recommendation: apply
       Checks-Effects-Interactions — update all state before making
       external calls, or use a nonReentrant mutex (ReentrancyGuard).

════════════════════════════════════════════════════════════
  CRITICAL 0  ·  HIGH 1  ·  MEDIUM 0  ·  LOW 0  ·  INFO 0
════════════════════════════════════════════════════════════
```

Notice:
- **`give_some`** — the actual Solidity function name, not a raw selector like `fn_0xe3d670d7()`
- **`Line 8:`** — the exact source line that triggered the finding

When analyzing raw bytecode (no `.sol` file), the function name falls back to the ABI signature and no source line is shown.

---

## Input formats

| Format | Example | Notes |
|--------|---------|-------|
| **Solidity source** | `ferrum -i MyContract.sol` | Compiled on-the-fly via `solc`; source map used for line-level findings |
| **Hex (bare)** | `6080604052...` | Via file or stdin |
| **Hex (0x-prefixed)** | `0x6080604052...` | Via file or stdin |
| **Raw binary** | `.bin` file | Via file or stdin |

For contracts that have already been compiled, you can also pipe bytecode directly:

```bash
# Foundry
jq -r '.deployedBytecode' out/MyContract.sol/MyContract.json | ferrum

# Hardhat
jq -r '.deployedBytecode' artifacts/contracts/MyContract.sol/MyContract.json | ferrum

# solc
solc --bin-runtime MyContract.sol 2>/dev/null | tail -n1 | ferrum
```

---

## Project structure

```
src/
├── opcodes.rs     Full EVM opcode set (Cancun: PUSH0, TLOAD/TSTORE, MCOPY)
├── disasm.rs      Bytecode → RawInsn list; hex/binary input parsing; CBOR metadata stripping
├── compile.rs     .sol → bytecode via solc (bin-runtime + srcmap-runtime + hashes);
│                  pc_to_source_line() maps a bytecode PC to a Solidity line;
│                  enclosing_function_name() scans source backward to find the
│                  function declaration that contains a given line
├── cfg.rs         Basic block identification; static JUMP resolution; CFG
├── lifter.rs      Stack simulation → SSA-like IR; ABI function detection
├── taint.rs       Forward BFS taint propagation (9 taint sources)
├── detectors.rs   13 vulnerability detectors on IR + taint map
├── output.rs      ANSI text / JSON / SARIF 2.1.0 formatters
├── lib.rs         Module declarations
└── main.rs        CLI (clap); .sol vs bytecode routing; source-location enrichment
```

---

## Limitations

**Computed jump targets** — jump destinations computed at runtime leave CFG edges missing. This is inherent to static analysis; symbolic execution (Mythril) handles these at ~1000× the cost.

**Solidity 0.8 subroutine pattern** — the compiler emits an internal calling convention (PUSH return_addr; PUSH helper; JUMP) for ABI decoding and SafeMath. The static CFG cannot resolve the dynamic return edge, so some blocks appear orphaned. Ferrum uses a bytecode-order heuristic to bridge this for reentrancy detection. Function names in findings are resolved by scanning the Solidity source backward from the buggy line, so they reflect the true enclosing function even when the CFG is incomplete. For bytecode-only input (no source file) the function name falls back to the ABI selector signature.

**External imports** — when a `.sol` file imports from npm packages (e.g. `@openzeppelin/contracts`), those packages must be resolvable by `solc` from the file's directory. For Foundry/Hardhat projects, run `ferrum` from the project root or ensure `node_modules` is present.

**Source line accuracy** — source lines are derived from `solc`'s runtime source map. Compiler-generated stubs (ABI decoder, SafeMath helpers) produce no source entry and are silently skipped; the finding will show only the PC in those cases.

**Memory taint** — taint is tracked over the SSA value graph (registers), not memory. Block variables encoded into memory via `abi.encodePacked` before being hashed are not detected by the WEAK-RANDOMNESS detector. Simple patterns (`keccak256(block.timestamp)` without encoding) are detected.

**Cross-function taint** — taint from one function call's return value is not propagated. Each analysis is intra-contract.

**No loop fixpoint** — the stack simulation is a single linear pass. Values at loop back-edges are not merged (no phi nodes). Rare for security patterns but can miss issues inside hot loops.

---

## License

AGPLv3
