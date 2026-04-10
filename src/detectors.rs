use std::collections::{HashSet, VecDeque};
use serde::Serialize;
use crate::opcodes::Opcode;
use crate::lifter::{IrProgram, ValId};
use crate::taint::{TaintMap, flags};

// ─────────────────────────────────────────────────────────────────────────────
// Finding types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High     => "HIGH",
            Severity::Medium   => "MEDIUM",
            Severity::Low      => "LOW",
            Severity::Info     => "INFO",
        }
    }

    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium                    => "warning",
            Severity::Low | Severity::Info      => "note",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity:           Severity,
    pub id:                 &'static str,
    pub title:              &'static str,
    pub description:        String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pc:                 Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_name:      Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_line_number: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_snippet:     Option<String>,
}

/// Metadata for --list-detectors output.
pub struct DetectorInfo {
    pub id:          &'static str,
    pub title:       &'static str,
    pub severity:    Severity,
    pub description: &'static str,
    pub swc:         Option<&'static str>,
}

pub fn list_all_detectors() -> Vec<DetectorInfo> {
    vec![
        DetectorInfo {
            id: "REENTRANCY", title: "Potential Reentrancy",
            severity: Severity::High, swc: Some("SWC-107"),
            description: "ETH-sending CALL followed by SSTORE on a reachable path — CEI pattern violated.",
        },
        DetectorInfo {
            id: "UNCHECKED-CALL", title: "Unchecked External Call Return Value",
            severity: Severity::Medium, swc: Some("SWC-104"),
            description: "Boolean success value of CALL/CALLCODE never tested in a conditional branch.",
        },
        DetectorInfo {
            id: "TX-ORIGIN-AUTH", title: "Use of tx.origin for Authentication",
            severity: Severity::High, swc: Some("SWC-115"),
            description: "ORIGIN (tx.origin) flows into a branch — susceptible to phishing attacks.",
        },
        DetectorInfo {
            id: "UNPROTECTED-SELFDESTRUCT", title: "SELFDESTRUCT Without Access Control",
            severity: Severity::Critical, swc: Some("SWC-106"),
            description: "SELFDESTRUCT with no msg.sender guard — any caller can destroy the contract.",
        },
        DetectorInfo {
            id: "SELFDESTRUCT-PRESENT", title: "SELFDESTRUCT Present",
            severity: Severity::Low, swc: Some("SWC-106"),
            description: "SELFDESTRUCT found; access control exists somewhere but path ownership unverified.",
        },
        DetectorInfo {
            id: "TIMESTAMP-DEPENDENCY", title: "Block Timestamp Dependency",
            severity: Severity::Low, swc: Some("SWC-116"),
            description: "block.timestamp used in a conditional branch — manipulable ±12 s by validators.",
        },
        DetectorInfo {
            id: "DELEGATECALL-CONTROLLED", title: "DELEGATECALL to User-Controlled Address",
            severity: Severity::Critical, swc: Some("SWC-112"),
            description: "DELEGATECALL target derived from calldata — attacker runs code in this contract's storage.",
        },
        DetectorInfo {
            id: "INTEGER-OVERFLOW", title: "Potential Integer Overflow",
            severity: Severity::High, swc: Some("SWC-101"),
            description: "ADD/MUL/EXP on user-controlled operand; result reaches persistent state.",
        },
        DetectorInfo {
            id: "INTEGER-UNDERFLOW", title: "Potential Integer Underflow",
            severity: Severity::High, swc: Some("SWC-101"),
            description: "SUB on user-controlled operand; result reaches persistent state.",
        },
        DetectorInfo {
            id: "ARBITRARY-JUMP", title: "Arbitrary Jump",
            severity: Severity::Critical, swc: Some("SWC-127"),
            description: "JUMP/JUMPI destination derived from calldata — attacker controls execution flow.",
        },
        DetectorInfo {
            id: "CONTROLLED-CALL-TARGET", title: "Call to User-Controlled Address",
            severity: Severity::High, swc: None,
            description: "CALL/CALLCODE/STATICCALL target derived from calldata.",
        },
        DetectorInfo {
            id: "WEAK-RANDOMNESS", title: "Weak Pseudo-Randomness",
            severity: Severity::Medium, swc: Some("SWC-120"),
            description: "Block variables (timestamp, blockhash, number, coinbase) used as randomness source.",
        },
        DetectorInfo {
            id: "STORAGE-COLLISION", title: "Proxy Storage Collision",
            severity: Severity::High, swc: None,
            description: "DELEGATECALL present and SSTORE to a low sequential slot — \
                           the implementation shares this contract's storage and can corrupt proxy state.",
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Forward BFS helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Does `start_val` eventually reach an SSTORE as the *value* argument (args[1])?
fn flows_to_sstore_value(prog: &IrProgram, start_val: ValId) -> bool {
    let mut visited = HashSet::new();
    let mut queue   = VecDeque::new();
    queue.push_back(start_val);
    while let Some(v) = queue.pop_front() {
        if !visited.insert(v) { continue; }
        if let Some(idxs) = prog.consumers.get(&v) {
            for &idx in idxs {
                let ir = &prog.all_insns[idx];
                if ir.op == Opcode::SStore && ir.args.get(1) == Some(&v) {
                    return true;
                }
                if let Some(res) = ir.result { queue.push_back(res); }
            }
        }
    }
    false
}

/// Does `start_val` eventually reach a CALL/CALLCODE as the *value* argument (args[2])?
fn flows_to_call_value(prog: &IrProgram, start_val: ValId) -> bool {
    let mut visited = HashSet::new();
    let mut queue   = VecDeque::new();
    queue.push_back(start_val);
    while let Some(v) = queue.pop_front() {
        if !visited.insert(v) { continue; }
        if let Some(idxs) = prog.consumers.get(&v) {
            for &idx in idxs {
                let ir = &prog.all_insns[idx];
                if matches!(ir.op, Opcode::Call | Opcode::CallCode)
                    && ir.args.get(2) == Some(&v) {
                    return true;
                }
                if let Some(res) = ir.result { queue.push_back(res); }
            }
        }
    }
    false
}

/// Does `start_val` eventually reach an MSTORE as the *value* argument (args[1])?
/// Used to detect block variables written to memory (likely as SHA3 input for RNG).
fn flows_to_mstore_value(prog: &IrProgram, start_val: ValId) -> bool {
    let mut visited = HashSet::new();
    let mut queue   = VecDeque::new();
    queue.push_back(start_val);
    while let Some(v) = queue.pop_front() {
        if !visited.insert(v) { continue; }
        if let Some(idxs) = prog.consumers.get(&v) {
            for &idx in idxs {
                let ir = &prog.all_insns[idx];
                if matches!(ir.op, Opcode::MStore | Opcode::MStore8)
                    && ir.args.get(1) == Some(&v) {
                    return true;
                }
                if let Some(res) = ir.result { queue.push_back(res); }
            }
        }
    }
    false
}

fn flows_to_branch(prog: &IrProgram, id: ValId) -> bool {
    prog.flows_to_jumpi(id)
}

/// True if the bytecode has a CALLER value that eventually controls a branch.
fn has_caller_check(prog: &IrProgram) -> bool {
    for ir in &prog.all_insns {
        if ir.op == Opcode::Caller {
            if let Some(result) = ir.result {
                if flows_to_branch(prog, result) { return true; }
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Reentrancy  (SWC-107)
// ─────────────────────────────────────────────────────────────────────────────

fn detect_reentrancy(prog: &IrProgram) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut reported: HashSet<usize> = HashSet::new();

    // Blocks with ETH-sending CALL/CALLCODE.
    //
    // NOTE: we intentionally do NOT require can_reach(0, off) here.  In Solidity
    // 0.8 contracts the function body often lives in "subroutine return target"
    // blocks (entered via a dynamic JUMP return from an ABI-decoder helper).
    // Those blocks have zero static predecessors so can_reach(0, …) returns false
    // even though the code is 100% live at runtime.
    let mut call_blocks: Vec<usize> = prog.blocks.keys()
        .filter(|&&off| prog.blocks[&off].insns.iter().any(|ir|
            matches!(ir.op, Opcode::Call | Opcode::CallCode)
            && !ir.args.get(2).map(|&v| prog.is_zero(v)).unwrap_or(false)
        ))
        .copied()
        .collect();
    call_blocks.sort_unstable();

    // All blocks containing SSTORE, sorted ascending so we find the first one.
    let mut sstore_blocks: Vec<usize> = prog.blocks.keys()
        .filter(|&&off| prog.blocks[&off].insns.iter().any(|ir| ir.op == Opcode::SStore))
        .copied()
        .collect();
    sstore_blocks.sort_unstable();

    for &call_off in &call_blocks {
        let call_pc = prog.blocks[&call_off].insns.iter()
            .find(|ir| matches!(ir.op, Opcode::Call | Opcode::CallCode))
            .map(|ir| ir.pc)
            .unwrap_or(call_off);

        if !reported.insert(call_pc) { continue; }

        // Find the earliest SSTORE that could be reached after this CALL.
        //
        // Two criteria (either suffices):
        //
        // 1. Static CFG reachability: prog.can_reach(call_off, sstore_off).
        //    Precise, but fails when the path runs through Solidity's internal
        //    subroutine convention (PUSH return_pc; PUSH helper; JUMP) because
        //    the return edge (helper → return_pc) is a dynamic jump that the
        //    static CFG cannot resolve.
        //
        // 2. Bytecode-order heuristic: sstore_off > call_off.
        //    Solidity places a function's arithmetic helpers *after* its call
        //    sites; the SSTORE inside the helper therefore has a higher PC than
        //    the CALL.  This catches the common SafeMath/checked-sub pattern
        //    that produces the classic CEI violation.
        let first_sstore_off = sstore_blocks.iter().copied().find(|&sstore_off| {
            if call_off == sstore_off {
                let blk = &prog.blocks[&call_off];
                let cp = blk.insns.iter().position(|ir| matches!(ir.op, Opcode::Call | Opcode::CallCode));
                let sp = blk.insns.iter().position(|ir| ir.op == Opcode::SStore);
                matches!((cp, sp), (Some(c), Some(s)) if c < s)
            } else {
                prog.can_reach(call_off, sstore_off) || sstore_off > call_off
            }
        });

        let sstore_off = match first_sstore_off { Some(o) => o, None => continue };

        let sstore_pc = prog.blocks[&sstore_off].insns.iter()
            .find(|ir| ir.op == Opcode::SStore)
            .map(|ir| ir.pc)
            .unwrap_or(sstore_off);

        findings.push(Finding {
            severity:      Severity::High,
            id:            "REENTRANCY",
            title:         "Potential Reentrancy",
            description:   format!(
                "CALL at {:#x} can reach SSTORE at {:#x} before state is updated. \
                 A re-entrant attacker can invoke this contract again during the external call \
                 and observe stale storage values. \
                 Recommendation: apply Checks-Effects-Interactions — update all state before \
                 making external calls, or use a nonReentrant mutex (ReentrancyGuard).",
                call_pc, sstore_pc
            ),
            pc:            Some(call_pc),
            function_name: prog.function_at(call_pc),
                source_line_number: None,
                source_snippet:     None,
        });
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Unchecked external call return value  (SWC-104)
// ─────────────────────────────────────────────────────────────────────────────

fn detect_unchecked_call(prog: &IrProgram) -> Vec<Finding> {
    let mut findings = Vec::new();

    for ir in &prog.all_insns {
        if !matches!(ir.op, Opcode::Call | Opcode::CallCode) { continue; }
        let result = match ir.result { Some(r) => r, None => continue };

        if !flows_to_branch(prog, result) {
            findings.push(Finding {
                severity:      Severity::Medium,
                id:            "UNCHECKED-CALL",
                title:         "Unchecked External Call Return Value",
                description:   format!(
                    "{} at {:#x}: the boolean success value is never tested in a conditional branch. \
                     A failed call silently continues execution, leaving the contract in an \
                     inconsistent state without any indication of failure. \
                     Recommendation: always check the return value with require(success, ...), \
                     use address.transfer() (auto-reverts), or OpenZeppelin Address.sendValue().",
                    ir.op.name(), ir.pc
                ),
                pc:            Some(ir.pc),
                function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
            });
        }
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. tx.origin authentication  (SWC-115)
// ─────────────────────────────────────────────────────────────────────────────

fn detect_tx_origin(prog: &IrProgram) -> Vec<Finding> {
    let mut findings = Vec::new();

    for ir in &prog.all_insns {
        if ir.op != Opcode::Origin { continue; }
        let result = match ir.result { Some(r) => r, None => continue };

        if flows_to_branch(prog, result) {
            findings.push(Finding {
                severity:      Severity::High,
                id:            "TX-ORIGIN-AUTH",
                title:         "Use of tx.origin for Authentication",
                description:   format!(
                    "ORIGIN at {:#x} flows into a conditional branch. \
                     tx.origin is the original EOA that initiated the transaction, not the direct caller. \
                     A malicious contract can relay a victim's call here, passing this check. \
                     This is the classic phishing-via-forwarding attack. \
                     Recommendation: replace tx.origin with msg.sender (CALLER) in all access control.",
                    ir.pc
                ),
                pc:            Some(ir.pc),
                function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
            });
        }
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Unprotected SELFDESTRUCT  (SWC-106)
// ─────────────────────────────────────────────────────────────────────────────

fn detect_selfdestruct(prog: &IrProgram) -> Vec<Finding> {
    let mut findings = Vec::new();
    let protected = has_caller_check(prog);

    for ir in &prog.all_insns {
        if ir.op != Opcode::SelfDestruct { continue; }

        if !protected {
            findings.push(Finding {
                severity:      Severity::Critical,
                id:            "UNPROTECTED-SELFDESTRUCT",
                title:         "SELFDESTRUCT Without Access Control",
                description:   format!(
                    "SELFDESTRUCT at {:#x}: no msg.sender (CALLER) check was found in the bytecode. \
                     Any caller can destroy this contract and sweep all its ether. \
                     Recommendation: add an onlyOwner check (or equivalent CALLER guard) \
                     before SELFDESTRUCT. Note: SELFDESTRUCT is deprecated post-Cancun (EIP-6780).",
                    ir.pc
                ),
                pc:            Some(ir.pc),
                function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
            });
        } else {
            findings.push(Finding {
                severity:      Severity::Low,
                id:            "SELFDESTRUCT-PRESENT",
                title:         "SELFDESTRUCT Present",
                description:   format!(
                    "SELFDESTRUCT at {:#x}: an access control check exists in the bytecode, \
                     but static analysis cannot confirm it guards this exact path. \
                     Recommendation: manually verify the owner check is on the correct execution path. \
                     Consider removing SELFDESTRUCT entirely (deprecated by EIP-6780 in Cancun).",
                    ir.pc
                ),
                pc:            Some(ir.pc),
                function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
            });
        }
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Block timestamp dependency  (SWC-116)
// ─────────────────────────────────────────────────────────────────────────────

fn detect_timestamp(prog: &IrProgram) -> Vec<Finding> {
    let mut findings = Vec::new();

    for ir in &prog.all_insns {
        if ir.op != Opcode::Timestamp { continue; }
        let result = match ir.result { Some(r) => r, None => continue };

        if flows_to_branch(prog, result) {
            findings.push(Finding {
                severity:      Severity::Low,
                id:            "TIMESTAMP-DEPENDENCY",
                title:         "Block Timestamp Dependency",
                description:   format!(
                    "TIMESTAMP at {:#x} flows into a conditional branch. \
                     Post-Merge validators can skew block.timestamp by ~12 seconds. \
                     Avoid strict equality (== timestamp), short deadlines, or randomness seeding. \
                     Recommendation: use block.number for approximate timing, \
                     a minimum interval of 15+ minutes for time-locks, \
                     or Chainlink VRF for randomness.",
                    ir.pc
                ),
                pc:            Some(ir.pc),
                function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
            });
        }
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. DELEGATECALL to user-controlled address  (SWC-112)
// ─────────────────────────────────────────────────────────────────────────────

fn detect_delegatecall(prog: &IrProgram, taint: &TaintMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    for ir in &prog.all_insns {
        if ir.op != Opcode::DelegateCall { continue; }
        // DELEGATECALL args: [gas, addr, argsOffset, argsLen, retOffset, retLen]
        if let Some(&addr_id) = ir.args.get(1) {
            if taint.has_flag(addr_id, flags::CALLDATA) {
                findings.push(Finding {
                    severity:      Severity::Critical,
                    id:            "DELEGATECALL-CONTROLLED",
                    title:         "DELEGATECALL to User-Controlled Address",
                    description:   format!(
                        "DELEGATECALL at {:#x}: the target address is derived from calldata. \
                         DELEGATECALL executes the target's code in THIS contract's storage context. \
                         An attacker can point it at a malicious contract and gain full read/write \
                         access to all storage slots, including owner and balances. \
                         Recommendation: hardcode the implementation address (immutable/constant) \
                         or gate it behind an owner-controlled whitelist.",
                        ir.pc
                    ),
                    pc:            Some(ir.pc),
                    function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
                });
            }
        }
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Integer overflow / underflow  (SWC-101)
// ─────────────────────────────────────────────────────────────────────────────

fn detect_integer_overflow(prog: &IrProgram, taint: &TaintMap) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut reported: HashSet<usize> = HashSet::new();

    for ir in &prog.all_insns {
        let (is_overflow, is_underflow) = match ir.op {
            Opcode::Add | Opcode::Mul | Opcode::Exp => (true, false),
            Opcode::Sub                              => (false, true),
            _ => continue,
        };

        // At least one operand must be user-supplied
        let user_taint = flags::CALLDATA | flags::VALUE;
        if !ir.args.iter().any(|&a| taint.has_flag(a, user_taint)) { continue; }

        let result = match ir.result { Some(r) => r, None => continue };

        // Flag only if the result reaches persistent state or an ether transfer
        if !flows_to_sstore_value(prog, result) && !flows_to_call_value(prog, result) {
            continue;
        }

        if reported.insert(ir.pc) {
            let (id, title, verb) = if is_overflow {
                ("INTEGER-OVERFLOW", "Potential Integer Overflow", "overflow")
            } else {
                debug_assert!(is_underflow);
                ("INTEGER-UNDERFLOW", "Potential Integer Underflow", "underflow")
            };
            findings.push(Finding {
                severity:      Severity::High,
                id,
                title,
                description:   format!(
                    "{} at {:#x}: user-controlled operand(s) in arithmetic without a visible {} \
                     guard; the result is written to storage or used in an ether transfer. \
                     In Solidity <0.8.0 this wraps silently, enabling balance inflation or fund theft. \
                     Recommendation: use Solidity ≥0.8.0 (built-in overflow checks), \
                     OpenZeppelin SafeMath, or explicit require() bounds checks.",
                    ir.op.name(), ir.pc, verb
                ),
                pc:            Some(ir.pc),
                function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
            });
        }
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Arbitrary jump  (SWC-127)
// ─────────────────────────────────────────────────────────────────────────────

/// Return true if `dest_id` could plausibly hold an attacker-controlled address.
///
/// Filters out two systematic false-positive sources:
///
/// 1. Concrete constants — Solidity uses `PUSH2 <return_pc>` for internal
///    subroutine call/return. That ValId is concrete and is never "arbitrary".
///
/// 2. Comparison results — EQ, LT, GT etc. produce only 0 or 1 and cannot
///    be meaningful jump targets; their taint arises from ABI selector checks.
fn is_address_like(prog: &IrProgram, dest_id: ValId) -> bool {
    if prog.concrete(dest_id).is_some() { return false; }
    if let Some(node) = prog.val(dest_id) {
        if matches!(node.op,
            Opcode::Eq | Opcode::Lt | Opcode::Gt | Opcode::SLt | Opcode::SGt | Opcode::IsZero
        ) { return false; }
    }
    true
}

/// True if `dest_id` can be traced back to CALLDATALOAD within `MAX_DEPTH`
/// backwards data-flow hops, following only arithmetic/bitwise operations.
///
/// A genuine arbitrary-jump destination is directly derived from calldata in
/// at most one arithmetic step (e.g. `jump(calldataload(4))` or
/// `jump(and(calldataload(4), mask))`).  Solidity's linear stack simulation
/// produces confused taint chains that are many hops long, so limiting depth
/// to 1 suppresses subroutine-return false positives while still catching all
/// real SWC-127 patterns.
fn is_shallow_calldata_origin(prog: &IrProgram, dest_id: ValId) -> bool {
    const MAX_DEPTH: usize = 1;
    let mut stack: Vec<(ValId, usize)> = vec![(dest_id, 0)];
    let mut visited = HashSet::new();

    while let Some((vid, depth)) = stack.pop() {
        if depth > MAX_DEPTH || !visited.insert(vid) { continue; }
        let node = match prog.val(vid) { Some(n) => n, None => continue };
        match node.op {
            // ── Calldata sources ──────────────────────────────────────────
            Opcode::CallDataLoad | Opcode::CallDataSize => return true,
            // ── Taint breaks here (NO_PROPAGATE analogues) ────────────────
            Opcode::SLoad | Opcode::MLoad | Opcode::Balance | Opcode::ExtCodeSize
            | Opcode::Gas | Opcode::Address | Opcode::SelfBalance | Opcode::CodeSize => continue,
            // ── Comparison ops produce 0/1, not addresses ─────────────────
            Opcode::Eq | Opcode::Lt | Opcode::Gt | Opcode::SLt | Opcode::SGt
            | Opcode::IsZero => continue,
            // ── Follow arithmetic / bitwise backwards ─────────────────────
            _ => {
                for &inp in &node.inputs {
                    stack.push((inp, depth + 1));
                }
            }
        }
    }
    false
}

fn detect_arbitrary_jump(prog: &IrProgram, taint: &TaintMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    for ir in &prog.all_insns {
        if !matches!(ir.op, Opcode::Jump | Opcode::JumpI) { continue; }
        // args[0] = destination for both JUMP and JUMPI
        if let Some(&dest_id) = ir.args.first() {
            if !taint.has_flag(dest_id, flags::CALLDATA) { continue; }
            if !is_address_like(prog, dest_id) { continue; }
            // Only flag when calldata is the shallow (≤2 hops) origin of the
            // destination value — suppresses subroutine-return false positives
            // from the linear stack simulator
            if !is_shallow_calldata_origin(prog, dest_id) { continue; }

            // Only flag JUMPs inside blocks that are statically reachable from
            // the entry point (block 0).  Solidity 0.8 ABI-decoder helper
            // subroutines are entered via dynamic jumps whose targets the CFG
            // resolver cannot statically track, so they appear as disconnected
            // islands in the CFG.  The linear stack simulator still processes
            // them, producing confused stack states and spurious findings.
            // Skipping unreachable blocks eliminates that class of noise.
            let block = prog.blocks.values()
                .find(|blk| ir.pc >= blk.offset && ir.pc < blk.end_pc);
            let block_off = block.map(|blk| blk.offset);
            let reachable_from_entry = block_off
                .map(|off| prog.can_reach(0, off))
                .unwrap_or(false);
            if !reachable_from_entry { continue; }

            // Skip shared subroutine return JUMPs.  A shared subroutine has
            // 2+ static predecessors and ALL of them end with an unconditional
            // JUMP (the subroutine-call pattern: PUSH return_addr; JUMP).
            // The JUMP at the end of such a block is a "return", not attacker-
            // controlled; the confused taint from the linear simulator is noise.
            if ir.op == Opcode::Jump {
                if let Some(blk) = block {
                    let all_preds_are_call_sites = !blk.preds.is_empty()
                        && blk.preds.iter().all(|&pred_off| {
                            prog.blocks.get(&pred_off)
                                .and_then(|pb| pb.insns.iter().rev()
                                    .find(|pi| pi.op != Opcode::JumpDest))
                                .map(|li| li.op == Opcode::Jump)
                                .unwrap_or(false)
                        });
                    if all_preds_are_call_sites { continue; }
                }
            }

            findings.push(Finding {
                severity:      Severity::Critical,
                id:            "ARBITRARY-JUMP",
                title:         "Arbitrary Jump via User-Controlled Destination",
                description:   format!(
                    "{} at {:#x}: the jump destination is derived from calldata. \
                     An attacker can redirect execution to any JUMPDEST in the bytecode, \
                     bypassing access control or reaching destructive code. \
                     This typically arises from unsafe inline assembly (assembly {{ jump(x) }}). \
                     Recommendation: never derive jump targets from user-supplied data.",
                    ir.op.name(), ir.pc
                ),
                pc:            Some(ir.pc),
                function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
            });
        }
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. CALL to user-controlled address
// ─────────────────────────────────────────────────────────────────────────────

fn detect_controlled_call_target(prog: &IrProgram, taint: &TaintMap) -> Vec<Finding> {
    let mut findings = Vec::new();

    for ir in &prog.all_insns {
        // DELEGATECALL has its own Critical detector; skip it here
        if !matches!(ir.op, Opcode::Call | Opcode::CallCode | Opcode::StaticCall) { continue; }

        // CALL/CALLCODE: [gas, addr, value, argsOff, argsLen, retOff, retLen]
        // STATICCALL:    [gas, addr, argsOff, argsLen, retOff, retLen]
        // In both layouts args[1] = target address
        if let Some(&addr_id) = ir.args.get(1) {
            if taint.has_flag(addr_id, flags::CALLDATA) {
                let severity = if ir.op == Opcode::StaticCall {
                    Severity::Medium  // STATICCALL can't mutate callee state
                } else {
                    Severity::High
                };
                findings.push(Finding {
                    severity,
                    id:            "CONTROLLED-CALL-TARGET",
                    title:         "Call to User-Controlled Address",
                    description:   format!(
                        "{} at {:#x}: the target address is derived from calldata. \
                         An attacker can redirect this call to a malicious contract, \
                         enabling callback exploits, token theft, or unintended state changes. \
                         Recommendation: validate the target address against an owner-controlled \
                         whitelist, or use a hardcoded/immutable trusted address.",
                        ir.op.name(), ir.pc
                    ),
                    pc:            Some(ir.pc),
                    function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
                });
            }
        }
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Weak pseudo-randomness  (SWC-120)
// ─────────────────────────────────────────────────────────────────────────────

fn detect_weak_randomness(prog: &IrProgram) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut reported: HashSet<usize> = HashSet::new();

    // Does this contract use SHA3 (KECCAK256) anywhere?
    let has_sha3 = prog.all_insns.iter().any(|ir| ir.op == Opcode::Sha3);

    let block_sources: &[(Opcode, &str)] = &[
        (Opcode::Timestamp,  "block.timestamp"),
        (Opcode::Number,     "block.number"),
        (Opcode::BlockHash,  "BLOCKHASH"),
        (Opcode::Prevrandao, "PREVRANDAO"),
        (Opcode::Coinbase,   "block.coinbase"),
    ];

    for ir in &prog.all_insns {
        let source_name = block_sources.iter()
            .find(|(op, _)| ir.op == *op)
            .map(|(_, n)| *n);
        let source_name = match source_name { Some(n) => n, None => continue };
        let result = match ir.result { Some(r) => r, None => continue };

        // Pattern 1: block variable stored directly (raw randomness seed in storage)
        if flows_to_sstore_value(prog, result) && reported.insert(ir.pc) {
            findings.push(Finding {
                severity:      Severity::Medium,
                id:            "WEAK-RANDOMNESS",
                title:         "Weak Pseudo-Randomness",
                description:   format!(
                    "{} ({}) at {:#x} flows directly to persistent storage. \
                     Storing a block variable as a randomness seed lets miners/validators \
                     predict or manipulate the outcome — a common attack on on-chain lotteries. \
                     Recommendation: use Chainlink VRF or a commit-reveal scheme.",
                    ir.op.name(), source_name, ir.pc
                ),
                pc:            Some(ir.pc),
                function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
            });
        }

        // Pattern 2: block variable written to memory in a contract that uses SHA3
        // (typical keccak-based RNG: keccak256(abi.encodePacked(block.timestamp, ...)))
        if has_sha3 && flows_to_mstore_value(prog, result) && reported.insert(ir.pc) {
            findings.push(Finding {
                severity:      Severity::Medium,
                id:            "WEAK-RANDOMNESS",
                title:         "Weak Pseudo-Randomness",
                description:   format!(
                    "{} ({}) at {:#x} is written to memory in a contract that uses KECCAK256. \
                     This suggests a keccak256(block.* ...) randomness pattern. \
                     Miners/validators can manipulate block variables to control the hash output. \
                     Recommendation: use Chainlink VRF for verifiable, unpredictable randomness.",
                    ir.op.name(), source_name, ir.pc
                ),
                pc:            Some(ir.pc),
                function_name: prog.function_at(ir.pc),
                source_line_number: None,
                source_snippet:     None,
            });
        }
    }
    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Proxy storage collision
// ─────────────────────────────────────────────────────────────────────────────

/// Known EIP-1967 unstructured storage slots (32 bytes each, big-endian).
/// These are safe to use in a proxy because they don't overlap with a
/// Solidity contract's sequential slot layout.
static EIP1967_SLOTS: &[[u8; 32]] = &[
    // bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
    [0x36,0x08,0x94,0xa1,0x3b,0xa1,0xa3,0x21,0x06,0x67,0xc8,0x28,0x49,0x2d,0xb9,0x8d,
     0xca,0x3e,0x20,0x76,0xcc,0x37,0x35,0xa9,0x20,0xa3,0xca,0x50,0x5d,0x38,0x2b,0xbc],
    // bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1)
    [0xb5,0x31,0x27,0x68,0x4a,0x56,0x8b,0x31,0x73,0xae,0x13,0xb9,0xf8,0xa6,0x01,0x6e,
     0x24,0x3e,0x63,0xb6,0xe8,0xee,0x11,0x78,0xd6,0xa7,0x17,0x85,0x0b,0x5d,0x61,0x03],
    // bytes32(uint256(keccak256("eip1967.proxy.rollback")) - 1)
    [0x49,0x10,0xfd,0xfa,0x16,0xfe,0xd3,0x26,0x0e,0xd0,0xe7,0x14,0x7f,0x7c,0xc6,0xda,
     0x11,0xa6,0x02,0x08,0xb5,0xb9,0x40,0x6d,0x12,0xa6,0x35,0x61,0x4f,0xfd,0x91,0x43],
    // bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1)
    [0xa3,0xf0,0xad,0x74,0xe5,0x42,0x3a,0xeb,0xfd,0x80,0xd3,0xef,0x43,0x46,0x57,0x83,
     0x35,0xa9,0xa7,0x2a,0xea,0xee,0x59,0xff,0x6c,0xb3,0x58,0x2b,0x35,0x13,0x3d,0x50],
];

/// Return true if `slot` is one of the known EIP-1967 unstructured storage slots.
fn is_eip1967(slot: &[u8; 32]) -> bool {
    EIP1967_SLOTS.iter().any(|s| s == slot)
}

/// Return true if the slot is "low" — i.e. the top 28 bytes are zero,
/// meaning the slot value fits in a u32.  These are sequential/direct
/// Solidity slots (slot 0, 1, 2, …) that collide with implementation layouts.
fn is_low_slot(slot: &[u8; 32]) -> bool {
    slot[..28].iter().all(|&b| b == 0)
}

fn detect_storage_collision(prog: &IrProgram) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Only a proxy pattern is affected: contract must use DELEGATECALL.
    let has_delegatecall = prog.all_insns.iter()
        .any(|ir| ir.op == Opcode::DelegateCall);
    if !has_delegatecall { return findings; }

    let mut reported: HashSet<usize> = HashSet::new();

    for ir in &prog.all_insns {
        if ir.op != Opcode::SStore { continue; }

        // Slot is the first argument to SSTORE.
        let slot_id = match ir.args.first() { Some(&id) => id, None => continue };
        let word    = match prog.concrete(slot_id) { Some(w) => w, None => continue };

        // Skip EIP-1967 compliant slots — those are intentionally collision-resistant.
        if is_eip1967(&word.0) { continue; }

        // Flag sequential/low slots only.
        if !is_low_slot(&word.0) { continue; }

        if !reported.insert(ir.pc) { continue; }

        findings.push(Finding {
            severity:      Severity::High,
            id:            "STORAGE-COLLISION",
            title:         "Proxy Storage Collision",
            description:   format!(
                "SSTORE to slot {} at {:#x} in a contract that also uses DELEGATECALL. \
                 DELEGATECALL executes the implementation's code in this contract's storage \
                 context, so any write the implementation makes to slot {} will overwrite \
                 this contract's own state variable at that slot (e.g. the implementation \
                 address, owner, or balance). \
                 Recommendation: store proxy-specific variables at EIP-1967 unstructured \
                 storage slots (keccak256-derived, e.g. 0x3608…) so they cannot be reached \
                 by the implementation's sequential layout.",
                word, ir.pc, word
            ),
            pc:            Some(ir.pc),
            function_name: prog.function_at(ir.pc),
            source_line_number: None,
            source_snippet:     None,
        });
    }

    findings
}

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

pub fn run_all(prog: &IrProgram, taint: &TaintMap) -> Vec<Finding> {
    let mut all: Vec<Finding> = Vec::new();
    all.extend(detect_reentrancy(prog));
    all.extend(detect_unchecked_call(prog));
    all.extend(detect_tx_origin(prog));
    all.extend(detect_selfdestruct(prog));
    all.extend(detect_timestamp(prog));
    all.extend(detect_delegatecall(prog, taint));
    all.extend(detect_integer_overflow(prog, taint));
    all.extend(detect_arbitrary_jump(prog, taint));
    all.extend(detect_controlled_call_target(prog, taint));
    all.extend(detect_weak_randomness(prog));
    all.extend(detect_storage_collision(prog));
    // Sort: Critical first, then by PC within each severity
    all.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.pc.cmp(&b.pc)));
    all
}
