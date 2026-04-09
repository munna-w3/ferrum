use std::collections::{HashMap, VecDeque};
use crate::opcodes::Opcode;
use crate::lifter::{IrProgram, ValId};

/// Bitmask constants for taint sources.
pub mod flags {
    pub const CALLDATA:       u8 = 1 << 0; // CALLDATALOAD / CALLDATASIZE
    pub const CALLER:         u8 = 1 << 1; // CALLER  (msg.sender)
    pub const ORIGIN:         u8 = 1 << 2; // ORIGIN  (tx.origin)
    pub const TIMESTAMP:      u8 = 1 << 3; // TIMESTAMP (block.timestamp)
    pub const BLOCKHASH:      u8 = 1 << 4; // BLOCKHASH / PREVRANDAO (miner-influenced)
    pub const VALUE:          u8 = 1 << 5; // CALLVALUE (msg.value)
    pub const NUMBER:         u8 = 1 << 6; // NUMBER  (block.number)
    pub const COINBASE:       u8 = 1 << 7; // COINBASE (block.coinbase / validator address)

    /// All block-variable taint flags — used for weak randomness detection.
    pub const BLOCK_INFLUENCE: u8 = TIMESTAMP | BLOCKHASH | NUMBER | COINBASE;

    pub fn describe(f: u8) -> String {
        let mut parts = Vec::new();
        if f & CALLDATA  != 0 { parts.push("calldata"); }
        if f & CALLER    != 0 { parts.push("msg.sender"); }
        if f & ORIGIN    != 0 { parts.push("tx.origin"); }
        if f & TIMESTAMP != 0 { parts.push("block.timestamp"); }
        if f & BLOCKHASH != 0 { parts.push("blockhash/prevrandao"); }
        if f & VALUE     != 0 { parts.push("msg.value"); }
        if f & NUMBER    != 0 { parts.push("block.number"); }
        if f & COINBASE  != 0 { parts.push("block.coinbase"); }
        if parts.is_empty() { "clean".into() } else { parts.join(", ") }
    }
}

/// Opcodes whose output should NOT propagate taint even if an input is tainted.
/// (These read stable on-chain state that resets provenance.)
const NO_PROPAGATE: &[Opcode] = &[
    Opcode::SLoad, Opcode::MLoad, Opcode::Balance, Opcode::ExtCodeSize,
    Opcode::Gas, Opcode::GasLimit, Opcode::Address, Opcode::SelfBalance,
    Opcode::CodeSize,
];

pub struct TaintMap {
    flags: HashMap<ValId, u8>,
}

impl TaintMap {
    pub fn get(&self, id: ValId) -> u8 {
        *self.flags.get(&id).unwrap_or(&0)
    }

    pub fn is_tainted(&self, id: ValId) -> bool {
        self.get(id) != 0
    }

    /// True if `id` has at least one bit from `flag` set.
    pub fn has_flag(&self, id: ValId, flag: u8) -> bool {
        self.get(id) & flag != 0
    }
}

/// Run forward BFS taint propagation over the IR value graph.
pub fn analyze(prog: &IrProgram) -> TaintMap {
    let mut flag_map: HashMap<ValId, u8> = HashMap::new();
    let mut queue: VecDeque<ValId> = VecDeque::new();

    // ── Seed taint sources ────────────────────────────────────────────────
    for ir in &prog.all_insns {
        let flag = match ir.op {
            Opcode::CallDataLoad | Opcode::CallDataSize => flags::CALLDATA,
            Opcode::Caller    => flags::CALLER,
            Opcode::Origin    => flags::ORIGIN,
            Opcode::Timestamp => flags::TIMESTAMP,
            // PREVRANDAO replaces DIFFICULTY post-Merge; still validator-influenced
            Opcode::BlockHash | Opcode::Prevrandao => flags::BLOCKHASH,
            Opcode::CallValue => flags::VALUE,
            Opcode::Number    => flags::NUMBER,
            Opcode::Coinbase  => flags::COINBASE,
            _ => 0,
        };
        if flag != 0 {
            if let Some(result) = ir.result {
                *flag_map.entry(result).or_insert(0) |= flag;
                queue.push_back(result);
            }
        }
    }

    // ── BFS propagation ───────────────────────────────────────────────────
    while let Some(v) = queue.pop_front() {
        let v_flags = match flag_map.get(&v) {
            Some(&f) if f != 0 => f,
            _ => continue,
        };

        let consumer_idxs = match prog.consumers.get(&v) {
            Some(idxs) => idxs.clone(),
            None => continue,
        };

        for idx in consumer_idxs {
            let ir = &prog.all_insns[idx];
            if NO_PROPAGATE.contains(&ir.op) {
                continue;
            }
            if let Some(result) = ir.result {
                let old = *flag_map.get(&result).unwrap_or(&0);
                let new = old | v_flags;
                if new != old {
                    *flag_map.entry(result).or_insert(0) = new;
                    queue.push_back(result);
                }
            }
        }
    }

    TaintMap { flags: flag_map }
}
