use std::collections::HashMap;
use crate::opcodes::Opcode;
use crate::disasm::RawInsn;
use crate::cfg::Cfg;

pub type ValId = u32;

/// A 256-bit EVM word stored big-endian.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Word(pub [u8; 32]);

impl Word {
    pub fn zero() -> Self {
        Word([0u8; 32])
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        let mut w = [0u8; 32];
        let n = b.len().min(32);
        w[32 - n..].copy_from_slice(&b[b.len() - n..]);
        Word(w)
    }

    pub fn as_usize(&self) -> Option<usize> {
        for i in 0..24 {
            if self.0[i] != 0 { return None; }
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&self.0[24..]);
        Some(usize::from_be_bytes(buf))
    }

    pub fn as_u32(&self) -> Option<u32> {
        for i in 0..28 {
            if self.0[i] != 0 { return None; }
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&self.0[28..]);
        Some(u32::from_be_bytes(buf))
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    pub fn to_hex(&self) -> String {
        let s: String = self.0.iter().map(|b| format!("{:02x}", b)).collect();
        format!("0x{}", s.trim_start_matches('0').to_string().as_str().to_string()
            .chars().take(64).collect::<String>())
    }
}

impl std::fmt::Display for Word {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show the minimal hex representation
        let hex: String = self.0.iter().map(|b| format!("{:02x}", b)).collect();
        let trimmed = hex.trim_start_matches('0');
        if trimmed.is_empty() {
            write!(f, "0x0")
        } else {
            write!(f, "0x{}", trimmed)
        }
    }
}

/// Metadata about a single SSA value.
#[derive(Debug, Clone)]
pub struct ValNode {
    pub id:       ValId,
    pub pc:       usize,
    pub op:       Opcode,
    pub inputs:   Vec<ValId>,
    pub concrete: Option<Word>,  // Some(_) if this is a compile-time constant
}

/// One instruction in the lifted IR.
#[derive(Debug, Clone)]
pub struct IrInsn {
    pub pc:     usize,
    pub op:     Opcode,
    pub result: Option<ValId>,
    pub args:   Vec<ValId>,
}

/// One basic block in the lifted IR.
#[derive(Debug, Clone)]
pub struct IrBlock {
    pub offset:     usize,
    pub end_pc:     usize,
    pub insns:      Vec<IrInsn>,
    pub succs:      Vec<usize>,
    pub preds:      Vec<usize>,
}

/// A recovered function (by ABI selector dispatch).
#[derive(Debug, Clone)]
pub struct IrFunction {
    pub offset:        usize,
    pub selector:      Option<u32>,
    pub name:          String,
    pub block_offsets: Vec<usize>,
}

/// The complete lifted program.
pub struct IrProgram {
    pub blocks:       HashMap<usize, IrBlock>,
    pub functions:    Vec<IrFunction>,
    pub val_nodes:    HashMap<ValId, ValNode>,
    /// All IR instructions in PC order (cross-block flat list).
    pub all_insns:    Vec<IrInsn>,
    /// ValId → indices into `all_insns` that consume it.
    pub consumers:    HashMap<ValId, Vec<usize>>,
    pub bytecode_len: usize,
}

impl IrProgram {
    /// Return the ValNode for an id.
    pub fn val(&self, id: ValId) -> Option<&ValNode> {
        self.val_nodes.get(&id)
    }

    /// Return true if `id` is a concrete value with value zero.
    pub fn is_zero(&self, id: ValId) -> bool {
        self.val_nodes.get(&id).and_then(|n| n.concrete.as_ref()).map(|w| w.is_zero()).unwrap_or(false)
    }

    /// Return the concrete word for `id`, if known.
    pub fn concrete(&self, id: ValId) -> Option<&Word> {
        self.val_nodes.get(&id)?.concrete.as_ref()
    }

    /// BFS forward: does `start_val` eventually flow into the condition argument of a JUMPI?
    pub fn flows_to_jumpi(&self, start_val: ValId) -> bool {
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(start_val);
        while let Some(v) = queue.pop_front() {
            if !visited.insert(v) { continue; }
            if let Some(idxs) = self.consumers.get(&v) {
                for &idx in idxs {
                    let insn = &self.all_insns[idx];
                    // For JUMPI: args[0]=dest, args[1]=condition
                    if insn.op == Opcode::JumpI && insn.args.get(1) == Some(&v) {
                        return true;
                    }
                    // Continue through single-output instructions (IsZero, Not, And, etc.)
                    if let Some(res) = insn.result {
                        queue.push_back(res);
                    }
                }
            }
        }
        false
    }

    /// BFS on block successors: can block `from` reach block `target`?
    pub fn can_reach(&self, from: usize, target: usize) -> bool {
        if from == target { return true; }
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(from);
        while let Some(cur) = queue.pop_front() {
            if !visited.insert(cur) { continue; }
            if let Some(blk) = self.blocks.get(&cur) {
                for &s in &blk.succs {
                    if s == target { return true; }
                    queue.push_back(s);
                }
            }
        }
        false
    }

    /// Name of the nearest function whose entry is at or before `pc`.
    pub fn function_at(&self, pc: usize) -> Option<String> {
        self.functions.iter()
            .filter(|f| f.offset <= pc)
            .max_by_key(|f| f.offset)
            .map(|f| f.name.clone())
    }

    /// All concrete storage slots written by SSTORE.
    pub fn sstore_slots(&self) -> Vec<Word> {
        let mut slots: Vec<Word> = Vec::new();
        for ir in &self.all_insns {
            if ir.op == Opcode::SStore {
                if let Some(&slot_id) = ir.args.first() {
                    if let Some(w) = self.concrete(slot_id) {
                        if !slots.contains(w) {
                            slots.push(w.clone());
                        }
                    }
                }
            }
        }
        slots
    }

    /// True if any CALL/CALLCODE sends non-zero ether, or SELFDESTRUCT is present.
    pub fn can_send_ether(&self) -> bool {
        for ir in &self.all_insns {
            match ir.op {
                Opcode::Call | Opcode::CallCode => {
                    let zero = ir.args.get(2).map(|&v| self.is_zero(v)).unwrap_or(false);
                    if !zero { return true; }
                }
                Opcode::SelfDestruct => return true,
                _ => {}
            }
        }
        false
    }

    /// Number of IR instructions (after DUP/SWAP/POP elision).
    pub fn insn_count(&self) -> usize {
        self.all_insns.len()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Stack simulation
// ──────────────────────────────────────────────────────────────────────────────

struct Lifter {
    val_counter: ValId,
    val_nodes:   HashMap<ValId, ValNode>,
    all_insns:   Vec<IrInsn>,
    stack:       Vec<ValId>,
}

impl Lifter {
    fn new() -> Self {
        Lifter {
            val_counter: 0,
            val_nodes:   HashMap::new(),
            all_insns:   Vec::new(),
            stack:       Vec::new(),
        }
    }

    fn new_val(&mut self, pc: usize, op: Opcode, inputs: Vec<ValId>, concrete: Option<Word>) -> ValId {
        let id = self.val_counter;
        self.val_counter += 1;
        self.val_nodes.insert(id, ValNode { id, pc, op, inputs, concrete });
        id
    }

    /// Pop from the simulated stack, creating a "param" value on underflow.
    fn pop(&mut self, pc: usize) -> ValId {
        if let Some(id) = self.stack.pop() {
            id
        } else {
            // Stack underflow — inject a symbolic parameter value
            self.new_val(pc, Opcode::Unknown(0xcc), vec![], None)
        }
    }

    fn process(&mut self, insn: &RawInsn) {
        match insn.op {
            // ── PUSH ──────────────────────────────────────────────────────
            Opcode::Push0 => {
                let id = self.new_val(insn.pc, Opcode::Push0, vec![], Some(Word::zero()));
                self.stack.push(id);
                self.all_insns.push(IrInsn { pc: insn.pc, op: insn.op, result: Some(id), args: vec![] });
            }
            Opcode::Push(_) => {
                let w = Word::from_bytes(&insn.imm);
                let id = self.new_val(insn.pc, insn.op, vec![], Some(w));
                self.stack.push(id);
                self.all_insns.push(IrInsn { pc: insn.pc, op: insn.op, result: Some(id), args: vec![] });
            }

            // ── DUP ───────────────────────────────────────────────────────
            Opcode::Dup(n) => {
                let n = n as usize;
                let len = self.stack.len();
                if n <= len {
                    let v = self.stack[len - n];
                    self.stack.push(v);
                } else {
                    let v = self.new_val(insn.pc, Opcode::Unknown(0xdd), vec![], None);
                    self.stack.push(v);
                }
                // DUP does not emit an IrInsn — it is a pure stack rearrangement
            }

            // ── SWAP ──────────────────────────────────────────────────────
            Opcode::Swap(n) => {
                let n = n as usize;
                let len = self.stack.len();
                if len >= n + 1 {
                    self.stack.swap(len - 1, len - 1 - n);
                }
                // SWAP does not emit an IrInsn
            }

            // ── POP ───────────────────────────────────────────────────────
            Opcode::Pop => {
                self.pop(insn.pc);
                // No IR instruction emitted
            }

            // ── JUMPDEST ──────────────────────────────────────────────────
            Opcode::JumpDest => {
                self.all_insns.push(IrInsn { pc: insn.pc, op: insn.op, result: None, args: vec![] });
            }

            // ── All other instructions ────────────────────────────────────
            _ => {
                let pops   = insn.op.pops();
                let pushes = insn.op.pushes();

                let args: Vec<ValId> = (0..pops).map(|_| self.pop(insn.pc)).collect();

                let result = if pushes > 0 {
                    let id = self.new_val(insn.pc, insn.op, args.clone(), None);
                    self.stack.push(id);
                    Some(id)
                } else {
                    None
                };

                self.all_insns.push(IrInsn { pc: insn.pc, op: insn.op, result, args });
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Public entry point
// ──────────────────────────────────────────────────────────────────────────────

pub fn lift(insns: &[RawInsn], cfg: &Cfg) -> IrProgram {
    let mut lifter = Lifter::new();

    // Linear simulation over all instructions in bytecode order
    for insn in insns {
        lifter.process(insn);
    }

    // Build consumer map: ValId → which all_insns indices use it
    let mut consumers: HashMap<ValId, Vec<usize>> = HashMap::new();
    for (idx, ir) in lifter.all_insns.iter().enumerate() {
        for &arg in &ir.args {
            consumers.entry(arg).or_default().push(idx);
        }
    }

    // Build IR blocks from CFG structure
    let mut blocks: HashMap<usize, IrBlock> = HashMap::new();
    for (&offset, bi) in &cfg.blocks {
        let insns_in_block: Vec<IrInsn> = lifter.all_insns
            .iter()
            .filter(|ir| ir.pc >= offset && ir.pc < bi.end_pc)
            .cloned()
            .collect();
        blocks.insert(offset, IrBlock {
            offset,
            end_pc: bi.end_pc,
            insns:  insns_in_block,
            succs:  bi.succs.clone(),
            preds:  bi.preds.clone(),
        });
    }

    let bytecode_len = insns.last().map(|r| r.pc + 1 + r.imm.len()).unwrap_or(0);

    let mut prog = IrProgram {
        blocks,
        functions: Vec::new(),
        val_nodes: lifter.val_nodes,
        all_insns: lifter.all_insns,
        consumers,
        bytecode_len,
    };

    detect_functions(&mut prog);
    prog
}

// ──────────────────────────────────────────────────────────────────────────────
// ABI function detection
// ──────────────────────────────────────────────────────────────────────────────

/// Known 4-byte function selectors → human-readable signatures.
static KNOWN_SELECTORS: &[(u32, &str)] = &[
    // ── ERC-20 ────────────────────────────────────────────────────────────
    (0x70a08231, "balanceOf(address)"),
    (0xa9059cbb, "transfer(address,uint256)"),
    (0x23b872dd, "transferFrom(address,address,uint256)"),
    (0x095ea7b3, "approve(address,uint256)"),
    (0xdd62ed3e, "allowance(address,address)"),
    (0x18160ddd, "totalSupply()"),
    (0x06fdde03, "name()"),
    (0x95d89b41, "symbol()"),
    (0x313ce567, "decimals()"),
    // ── Ownable ───────────────────────────────────────────────────────────
    (0xf2fde38b, "transferOwnership(address)"),
    (0x8da5cb5b, "owner()"),
    (0x715018a6, "renounceOwnership()"),
    // ── ETH handling ──────────────────────────────────────────────────────
    (0xd0e30db0, "deposit()"),
    (0x2e1a7d4d, "withdraw(uint256)"),
    (0x853828b6, "withdrawAll()"),
    (0xb6b55f25, "deposit(uint256)"),
    (0x3ccfd60b, "withdraw()"),
    (0x51cff8d9, "withdraw(address)"),
    (0x12065fe0, "getBalance()"),
    (0x893d20e8, "getOwner()"),
    // ── Staking / yield ───────────────────────────────────────────────────
    (0xa694fc3a, "stake(uint256)"),
    (0x2e17de78, "unstake(uint256)"),
    (0x4641257d, "harvest()"),
    (0x3d18b912, "getReward()"),
    (0xe9fad8ee, "exit()"),
    // ── Minting / burning ─────────────────────────────────────────────────
    (0x1249c58b, "mint()"),
    (0x40c10f19, "mint(address,uint256)"),
    (0x42966c68, "burn(uint256)"),
    (0x79cc6790, "burnFrom(address,uint256)"),
    (0x449a52f8, "mintTo(address,uint256)"),
    // ── Pausable ──────────────────────────────────────────────────────────
    (0x8456cb59, "pause()"),
    (0x3f4ba83a, "unpause()"),
    (0x5c975abb, "paused()"),
    // ── Upgradeable proxy ─────────────────────────────────────────────────
    (0x4f1ef286, "upgradeToAndCall(address,bytes)"),
    (0x3659cfe6, "upgradeTo(address)"),
    (0x52d1902d, "proxiableUUID()"),
    (0x54fd4d50, "version()"),
    // ── ERC-721 (NFT) ─────────────────────────────────────────────────────
    (0x6352211e, "ownerOf(uint256)"),
    (0x42842e0e, "safeTransferFrom(address,address,uint256)"),
    (0xb88d4fde, "safeTransferFrom(address,address,uint256,bytes)"),
    (0xe985e9c5, "isApprovedForAll(address,address)"),
    (0xa22cb465, "setApprovalForAll(address,bool)"),
    (0x081812fc, "getApproved(uint256)"),
    (0xc87b56dd, "tokenURI(uint256)"),
    (0x4e0f3805, "totalMinted()"),
    // ── ERC-1155 ──────────────────────────────────────────────────────────
    (0x00fdd58e, "balanceOf(address,uint256)"),
    (0x4e1273f4, "balanceOfBatch(address[],uint256[])"),
    (0x2eb2c2d6, "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)"),
    (0xf242432a, "safeTransferFrom(address,address,uint256,uint256,bytes)"),
    // ── OpenZeppelin AccessControl ────────────────────────────────────────
    (0x2f2ff15d, "grantRole(bytes32,address)"),
    (0xd547741f, "revokeRole(bytes32,address)"),
    (0x91d14854, "hasRole(bytes32,address)"),
    (0x248a9ca3, "getRoleAdmin(bytes32)"),
    (0x36568abe, "renounceRole(bytes32,address)"),
    // ── Initialization ────────────────────────────────────────────────────
    (0x8129fc1c, "initialize()"),
    (0x485cc955, "initialize(address,address)"),
    (0xc4d66de8, "initialize(address)"),
    // ── Chainlink price feeds ─────────────────────────────────────────────
    (0x50d25bcd, "latestAnswer()"),
    (0x668a0f02, "latestRound()"),
    (0xfeaf968c, "latestRoundData()"),
    (0x9a6fc8f5, "getRoundData(uint80)"),
    // ── Uniswap V2 Router ─────────────────────────────────────────────────
    (0x38ed1739, "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)"),
    (0x8803dbee, "swapTokensForExactTokens(uint256,uint256,address[],address,uint256)"),
    (0x7ff36ab5, "swapExactETHForTokens(uint256,address[],address,uint256)"),
    (0x18cbafe5, "swapExactTokensForETH(uint256,uint256,address[],address,uint256)"),
    (0xd06ca61f, "getAmountsOut(uint256,address[])"),
    (0xe8e33700, "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)"),
    (0x02751cec, "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)"),
    // ── Uniswap V2 Pair ───────────────────────────────────────────────────
    (0x0902f1ac, "getReserves()"),
    (0x6a627842, "mint(address)"),
    (0x89afcb44, "burn(address)"),
    (0xd9254be7, "swap(uint256,uint256,address,bytes)"),
    // ── Flash loans ───────────────────────────────────────────────────────
    (0xab9c4b5d, "flashLoan(address,address,uint256,bytes)"),
    (0x5cffe9de, "flashLoanSimple(address,address,uint256,bytes,uint16)"),
    // ── OpenZeppelin TimelockController ───────────────────────────────────
    (0x01d5062a, "schedule(address,uint256,bytes,bytes32,bytes32,uint256)"),
    (0x134008d3, "execute(address,uint256,bytes,bytes32,bytes32)"),
    (0xc4d252f5, "cancel(bytes32)"),
    // ── CTF / known-vulnerable patterns ──────────────────────────────────
    (0xbf0adeb7, "claimThrone()"),
    (0x43d726d6, "sweepCommission()"),
    (0x9e5faafc, "attack()"),
    (0x60fe47b1, "set(uint256)"),
    (0x6d4ce63c, "get()"),
];

fn selector_name(sel: u32) -> Option<&'static str> {
    KNOWN_SELECTORS.iter().find(|(s, _)| *s == sel).map(|(_, n)| *n)
}

/// Scan the IR for ABI dispatch patterns and populate `prog.functions`.
///
/// Pattern: EQ(selector_const, calldataload_derived) → JUMPI(target, eq_result)
fn detect_functions(prog: &mut IrProgram) {
    let mut functions: Vec<IrFunction> = Vec::new();
    // Collect all function entry offsets we find
    let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for ir in &prog.all_insns {
        if ir.op != Opcode::Eq {
            continue;
        }
        let result_id = match ir.result {
            Some(id) => id,
            None => continue,
        };

        // One of the two EQ arguments must be a 4-byte concrete value
        let selector = ir.args.iter().find_map(|&arg| {
            let node = prog.val_nodes.get(&arg)?;
            let w = node.concrete.as_ref()?;
            // Must be a non-zero 4-byte value (top 28 bytes zero)
            for i in 0..28 {
                if w.0[i] != 0 { return None; }
            }
            let v = u32::from_be_bytes([w.0[28], w.0[29], w.0[30], w.0[31]]);
            // Real keccak-4 selectors have high entropy; the top byte (w.0[28])
            // is statistically non-zero (probability 255/256).  Small constants
            // (< 0x01000000) are internal ABI type-check values, not function
            // selectors — skip them to avoid spurious function detections.
            if v < 0x0100_0000 { return None; }
            Some(v)
        });

        let selector = match selector {
            Some(s) => s,
            None => continue,
        };

        // Find the JUMPI that uses this EQ result (possibly through ISZERO)
        if let Some(target_offset) = find_jumpi_target(prog, result_id) {
            if seen.insert(target_offset) {
                let name = selector_name(selector)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("fn_{:#010x}()", selector));

                let block_offsets = prog.blocks.keys()
                    .filter(|&&off| off >= target_offset)
                    .copied()
                    .collect();

                functions.push(IrFunction {
                    offset: target_offset,
                    selector: Some(selector),
                    name,
                    block_offsets,
                });
            }
        }
    }

    // Sort by offset for stable output
    functions.sort_by_key(|f| f.offset);
    prog.functions = functions;
}

/// Given an EQ result ValId, follow ISZERO chains to find the JUMPI target.
fn find_jumpi_target(prog: &IrProgram, eq_result: ValId) -> Option<usize> {
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(eq_result);
    let mut visited = std::collections::HashSet::new();

    while let Some(v) = queue.pop_front() {
        if !visited.insert(v) { continue; }
        if let Some(idxs) = prog.consumers.get(&v) {
            for &idx in idxs {
                let ir = &prog.all_insns[idx];
                if ir.op == Opcode::JumpI {
                    // args[0] = destination, args[1] = condition
                    if let Some(&dest_id) = ir.args.first() {
                        if let Some(w) = prog.concrete(dest_id) {
                            return w.as_usize();
                        }
                    }
                }
                if ir.op == Opcode::IsZero {
                    if let Some(res) = ir.result {
                        queue.push_back(res);
                    }
                }
            }
        }
    }
    None
}
