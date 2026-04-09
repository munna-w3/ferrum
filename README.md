# Ferrum

**EVM bytecode security analyzer — written in Rust.**

Ferrum disassembles Ethereum smart contract bytecode, lifts it to an SSA-like intermediate representation, runs forward taint analysis, and reports security vulnerabilities with severity levels, precise locations, and remediation guidance.

Built as a faster, more capable successor to Python-based tools (Mythril, Rattle) with zero dependencies and sub-millisecond analysis.

---

## What it does

### Analysis pipeline

```
bytecode (hex / binary)
        │
        ▼
  Disassembler          — full EVM opcode set incl. PUSH0, TLOAD/TSTORE, MCOPY (Cancun)
        │
        ▼
  CFG Builder           — basic block identification, static jump target resolution
        │
        ▼
  IR Lifter             — stack simulation → SSA-like value graph
                          ABI function detection from 4-byte selector dispatch
        │
        ▼
  Taint Analysis        — forward BFS from user-controlled sources
                          (calldata, msg.sender, msg.value, tx.origin,
                           block.timestamp, blockhash, block.number,
                           block.coinbase, prevrandao)
        │
        ▼
  Vulnerability Detectors  (10 detectors, see table below)
        │
        ▼
  Output  (colored text / JSON / SARIF 2.1.0)
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

### How it compares to Mythril and Rattle

| Feature | Rattle | Mythril | Ferrum |
|---------|--------|---------|--------|
| Vulnerability detectors | None | ~10 (symbolic) | 12 (taint + CFG) |
| Detection approach | — | Symbolic execution | Taint + static CFG |
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

---

## Usage

```
ferrum [OPTIONS]

Options:
  -i, --input <FILE>      Input EVM bytecode (hex or raw binary); stdin if omitted
  -j, --json              Emit results as JSON
      --sarif             Emit results as SARIF 2.1.0 (GitHub Code Scanning)
      --disasm            Print disassembled opcodes and exit
      --list-detectors    Print all detectors with severity/SWC and exit
  -o, --output <FILE>     Write output to FILE instead of stdout
      --color             Force ANSI color even when stdout is not a TTY
      --no-color          Suppress ANSI color codes
  -h, --help              Print help
  -V, --version           Print version
```

### Analyze a contract

```bash
ferrum -i contract.bin
```

### Read from stdin (hex string)

```bash
echo "6080604052..." | ferrum
# or from a file
cat contract.bin | ferrum
```

### JSON output for scripting

```bash
ferrum -i contract.bin --json
ferrum -i contract.bin --json -o report.json
```

### SARIF for GitHub Code Scanning

```bash
ferrum -i contract.bin --sarif > results.sarif
# upload via upload-sarif action in CI
```

### List all detectors

```bash
ferrum --list-detectors
```

### Disassembly only

```bash
ferrum -i contract.bin --disasm
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No CRITICAL or HIGH findings |
| `1` | At least one CRITICAL or HIGH finding (or I/O error) |

CI pipeline example:

```yaml
- name: Security scan
  run: ferrum -i build/MyContract.bin --sarif -o ferrum.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ferrum.sarif
```

---

## Example output

Running on the classic EtherStore reentrancy-vulnerable contract:

```
════════════════════════════════════════════════════════════
  FERRUM  ·  EVM Security Analyzer  ·  Rust Edition
════════════════════════════════════════════════════════════

  Bytecode  :  1358 bytes  ·  514 opcodes  ·  98 blocks

  Identified Functions
  ────────────────────────────────────────
  0x0037  fn_0x27e235e3()    [0x27e235e3]
  0x0073  withdraw(uint256)  [0x2e1a7d4d]
  0x009b  deposit()          [0xd0e30db0]

  Storage slots :  0x22b, 0x281
  Sends ether   :  yes

  Security Findings
  ────────────────────────────────────────

  [1]  HIGH      ·  Potential Reentrancy
       deposit() @ 0x169
       CALL at 0x169 can reach SSTORE at 0x231 before state is updated.
       A re-entrant attacker can invoke this contract again during the
       external call and observe stale storage values. Recommendation:
       apply Checks-Effects-Interactions — update all state before making
       external calls, or use a nonReentrant mutex (ReentrancyGuard).

════════════════════════════════════════════════════════════
  CRITICAL 0  ·  HIGH 1  ·  MEDIUM 0  ·  LOW 0  ·  INFO 0
════════════════════════════════════════════════════════════
```

---

## Input formats

Ferrum auto-detects input format:

- **ASCII hex** — `6080604052...` with or without `0x` prefix
- **Raw binary** — the raw bytecode bytes
- **Whitespace / newlines** ignored in hex mode

Solidity `--bin-runtime`:

```bash
solc --bin-runtime MyContract.sol 2>/dev/null | tail -n1 | ferrum
```

Foundry / Hardhat:

```bash
jq -r '.deployedBytecode' out/MyContract.sol/MyContract.json | ferrum
```

---

## Project structure

```
src/
├── opcodes.rs     Full EVM opcode set (Cancun: PUSH0, TLOAD/TSTORE, MCOPY)
├── disasm.rs      Bytecode → RawInsn list; CBOR metadata stripping
├── cfg.rs         Basic block identification; static JUMP resolution; CFG
├── lifter.rs      Stack simulation → SSA-like IR; ABI function detection
├── taint.rs       Forward BFS taint propagation (9 taint sources)
├── detectors.rs   12 vulnerability detectors on IR + taint map
├── output.rs      ANSI text / JSON / SARIF 2.1.0 formatters
├── lib.rs         Module declarations
└── main.rs        CLI (clap)
```

---

## Limitations

**Computed jump targets** — jump destinations computed at runtime leave CFG edges missing. This is inherent to static analysis; symbolic execution (Mythril) handles these at ~1000× the cost.

**Solidity 0.8 subroutine pattern** — the compiler emits an internal calling convention (PUSH return_addr; PUSH helper; JUMP) for ABI decoding and SafeMath. The static CFG cannot resolve the dynamic return edge, so some blocks appear orphaned. Ferrum uses a bytecode-order heuristic to bridge this for reentrancy detection, but function attribution in findings may show the nearest-preceding function name rather than the true enclosing function.

**Memory taint** — taint is tracked over the SSA value graph (registers), not memory. Block variables encoded into memory via `abi.encodePacked` before being hashed are not detected by the WEAK-RANDOMNESS detector. Simple patterns (`keccak256(block.timestamp)` without encoding) are detected.

**Cross-function taint** — taint from one function call's return value is not propagated. Each analysis is intra-contract.

**No loop fixpoint** — the stack simulation is a single linear pass. Values at loop back-edges are not merged (no phi nodes). Rare for security patterns but can miss issues inside hot loops.

---

## License

AGPLv3
