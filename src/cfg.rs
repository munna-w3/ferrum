use std::collections::{HashMap, HashSet};
use crate::disasm::RawInsn;
use crate::opcodes::Opcode;

/// Lightweight block descriptor — just connectivity.
#[derive(Debug, Clone, Default)]
pub struct BlockInfo {
    pub offset: usize,
    pub end_pc: usize,          // PC of first byte of next block (exclusive)
    pub succs:  Vec<usize>,     // successor block offsets
    pub preds:  Vec<usize>,     // predecessor block offsets
}

#[derive(Debug, Default)]
pub struct Cfg {
    pub blocks: HashMap<usize, BlockInfo>,
    pub entry:  usize,
}

impl Cfg {
    pub fn block_at(&self, offset: usize) -> Option<&BlockInfo> {
        self.blocks.get(&offset)
    }

    /// BFS reachability: can we reach `target` from `from`?
    pub fn can_reach(&self, from: usize, target: usize) -> bool {
        if from == target {
            return true;
        }
        let mut visited = HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(from);
        visited.insert(from);
        while let Some(cur) = queue.pop_front() {
            if let Some(bi) = self.blocks.get(&cur) {
                for &s in &bi.succs {
                    if s == target {
                        return true;
                    }
                    if visited.insert(s) {
                        queue.push_back(s);
                    }
                }
            }
        }
        false
    }

    /// All blocks reachable from `from` (includes `from` itself).
    pub fn reachable_from(&self, from: usize) -> HashSet<usize> {
        let mut visited = HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(from);
        while let Some(cur) = queue.pop_front() {
            if visited.insert(cur) {
                if let Some(bi) = self.blocks.get(&cur) {
                    for &s in &bi.succs {
                        queue.push_back(s);
                    }
                }
            }
        }
        visited
    }
}

/// Build a CFG from a disassembled instruction list.
pub fn build_cfg(insns: &[RawInsn]) -> Cfg {
    if insns.is_empty() {
        return Cfg::default();
    }

    // ── 1. Identify block-start offsets ───────────────────────────────────
    let mut starts: HashSet<usize> = HashSet::new();
    starts.insert(0);

    let pc_to_idx: HashMap<usize, usize> = insns.iter().enumerate().map(|(i, r)| (r.pc, i)).collect();
    let max_pc = insns.last().map(|r| r.pc + 1 + r.imm.len()).unwrap_or(0);

    for (idx, insn) in insns.iter().enumerate() {
        if insn.op == Opcode::JumpDest {
            starts.insert(insn.pc);
        }
        if insn.op.is_terminator() {
            // Instruction after a terminator starts a new block
            let next_pc = insn.pc + 1 + insn.imm.len();
            if next_pc < max_pc {
                starts.insert(next_pc);
            }
        }
        // JUMPI fall-through target
        if insn.op == Opcode::JumpI {
            let next_pc = insn.pc + 1;
            if next_pc < max_pc {
                starts.insert(next_pc);
            }
        }
        let _ = idx;
    }

    let mut starts_sorted: Vec<usize> = starts.into_iter().collect();
    starts_sorted.sort_unstable();

    // ── 2. Build BlockInfo for each block ─────────────────────────────────
    let mut blocks: HashMap<usize, BlockInfo> = HashMap::new();
    for (i, &start) in starts_sorted.iter().enumerate() {
        let end = if i + 1 < starts_sorted.len() { starts_sorted[i + 1] } else { max_pc };
        blocks.insert(start, BlockInfo { offset: start, end_pc: end, succs: vec![], preds: vec![] });
    }

    // ── 3. Resolve edges ──────────────────────────────────────────────────
    // We need a helper to find the last instruction of each block.
    let block_last_insn: HashMap<usize, &RawInsn> = {
        let mut m = HashMap::new();
        for (&start, bi) in &blocks {
            // Find last instruction before bi.end_pc
            let last = insns.iter().rev().find(|r| r.pc >= start && r.pc < bi.end_pc);
            if let Some(l) = last {
                m.insert(start, l);
            }
        }
        m
    };

    let mut succ_map: HashMap<usize, Vec<usize>> = HashMap::new();

    for (&start, bi) in &blocks {
        let mut succs: Vec<usize> = Vec::new();
        if let Some(&last) = block_last_insn.get(&start) {
            match last.op {
                Opcode::Jump => {
                    // Look backwards for a PUSH that loads the jump target
                    if let Some(target) = resolve_jump_target(insns, last, &pc_to_idx) {
                        if blocks.contains_key(&target) {
                            succs.push(target);
                        }
                    }
                    // Unconditional — no fall-through
                }
                Opcode::JumpI => {
                    // Conditional: taken target + fall-through
                    if let Some(target) = resolve_jump_target(insns, last, &pc_to_idx) {
                        if blocks.contains_key(&target) {
                            succs.push(target);
                        }
                    }
                    let ft = last.pc + 1;
                    if blocks.contains_key(&ft) {
                        succs.push(ft);
                    }
                }
                op if !op.is_terminator() => {
                    // Non-terminating last insn — fall through
                    if blocks.contains_key(&bi.end_pc) {
                        succs.push(bi.end_pc);
                    }
                }
                _ => {} // STOP / RETURN / REVERT / etc. — no successors
            }
        }
        succ_map.insert(start, succs);
    }

    // Commit succs and build preds
    for (&start, succs) in &succ_map {
        blocks.get_mut(&start).unwrap().succs = succs.clone();
    }
    // Build predecessor lists
    let offsets: Vec<usize> = blocks.keys().copied().collect();
    for src in offsets {
        let succs = blocks[&src].succs.clone();
        for dst in succs {
            if let Some(dst_block) = blocks.get_mut(&dst) {
                if !dst_block.preds.contains(&src) {
                    dst_block.preds.push(src);
                }
            }
        }
    }

    Cfg { blocks, entry: 0 }
}

/// Try to statically resolve the jump target for a JUMP/JUMPI instruction
/// by looking at the PUSH that immediately precedes it on the stack.
fn resolve_jump_target(
    insns: &[RawInsn],
    jump_insn: &RawInsn,
    pc_to_idx: &HashMap<usize, usize>,
) -> Option<usize> {
    let idx = *pc_to_idx.get(&jump_insn.pc)?;
    // Walk backwards skipping non-stack-affecting instructions
    for i in (0..idx).rev() {
        let prev = &insns[i];
        match prev.op {
            Opcode::Push(_) | Opcode::Push0 => {
                return prev.push_target();
            }
            // These don't affect the top-of-stack position we care about
            Opcode::JumpDest => continue,
            // Anything else could modify the stack — give up
            _ => break,
        }
    }
    None
}
