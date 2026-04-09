/// Full EVM opcode set including post-Cancun extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    // ── Arithmetic ─────────────────────────────────────────────────────────
    Stop,
    Add, Mul, Sub, Div, SDiv, Mod, SMod, AddMod, MulMod, Exp, SignExtend,
    // ── Comparison ─────────────────────────────────────────────────────────
    Lt, Gt, SLt, SGt, Eq, IsZero,
    // ── Bitwise ────────────────────────────────────────────────────────────
    And, Or, Xor, Not, Byte, Shl, Shr, Sar,
    // ── Hash ───────────────────────────────────────────────────────────────
    Sha3,
    // ── Environment ────────────────────────────────────────────────────────
    Address, Balance, Origin, Caller, CallValue,
    CallDataLoad, CallDataSize, CallDataCopy,
    CodeSize, CodeCopy, GasPrice,
    ExtCodeSize, ExtCodeCopy,
    ReturnDataSize, ReturnDataCopy, ExtCodeHash,
    // ── Block ──────────────────────────────────────────────────────────────
    BlockHash, Coinbase, Timestamp, Number, Prevrandao, GasLimit,
    ChainId, SelfBalance, BaseFee, BlobHash, BlobBaseFee,
    // ── Stack / Memory / Storage ───────────────────────────────────────────
    Pop, MLoad, MStore, MStore8,
    SLoad, SStore,
    // ── Control flow ───────────────────────────────────────────────────────
    Jump, JumpI, Pc, MSize, Gas, JumpDest,
    // ── Transient storage (EIP-1153, Cancun) ───────────────────────────────
    TLoad, TStore,
    // ── Memory copy (EIP-5656, Cancun) ─────────────────────────────────────
    MCopy,
    // ── Push (EIP-3855 PUSH0 + PUSH1..PUSH32) ──────────────────────────────
    Push0,
    Push(u8),   // u8 = immediate byte count (1–32)
    // ── Stack manipulation ─────────────────────────────────────────────────
    Dup(u8),    // DUP1–DUP16 — u8 = depth (1–16)
    Swap(u8),   // SWAP1–SWAP16 — u8 = depth (1–16)
    // ── Logging ────────────────────────────────────────────────────────────
    Log(u8),    // LOG0–LOG4 — u8 = topic count (0–4)
    // ── System ─────────────────────────────────────────────────────────────
    Create, Call, CallCode, Return, DelegateCall, Create2, StaticCall,
    Revert, Invalid, SelfDestruct,
    Unknown(u8),
}

impl Opcode {
    /// Decode a single byte into an opcode.
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Opcode::Stop,
            0x01 => Opcode::Add,
            0x02 => Opcode::Mul,
            0x03 => Opcode::Sub,
            0x04 => Opcode::Div,
            0x05 => Opcode::SDiv,
            0x06 => Opcode::Mod,
            0x07 => Opcode::SMod,
            0x08 => Opcode::AddMod,
            0x09 => Opcode::MulMod,
            0x0a => Opcode::Exp,
            0x0b => Opcode::SignExtend,
            0x10 => Opcode::Lt,
            0x11 => Opcode::Gt,
            0x12 => Opcode::SLt,
            0x13 => Opcode::SGt,
            0x14 => Opcode::Eq,
            0x15 => Opcode::IsZero,
            0x16 => Opcode::And,
            0x17 => Opcode::Or,
            0x18 => Opcode::Xor,
            0x19 => Opcode::Not,
            0x1a => Opcode::Byte,
            0x1b => Opcode::Shl,
            0x1c => Opcode::Shr,
            0x1d => Opcode::Sar,
            0x20 => Opcode::Sha3,
            0x30 => Opcode::Address,
            0x31 => Opcode::Balance,
            0x32 => Opcode::Origin,
            0x33 => Opcode::Caller,
            0x34 => Opcode::CallValue,
            0x35 => Opcode::CallDataLoad,
            0x36 => Opcode::CallDataSize,
            0x37 => Opcode::CallDataCopy,
            0x38 => Opcode::CodeSize,
            0x39 => Opcode::CodeCopy,
            0x3a => Opcode::GasPrice,
            0x3b => Opcode::ExtCodeSize,
            0x3c => Opcode::ExtCodeCopy,
            0x3d => Opcode::ReturnDataSize,
            0x3e => Opcode::ReturnDataCopy,
            0x3f => Opcode::ExtCodeHash,
            0x40 => Opcode::BlockHash,
            0x41 => Opcode::Coinbase,
            0x42 => Opcode::Timestamp,
            0x43 => Opcode::Number,
            0x44 => Opcode::Prevrandao,
            0x45 => Opcode::GasLimit,
            0x46 => Opcode::ChainId,
            0x47 => Opcode::SelfBalance,
            0x48 => Opcode::BaseFee,
            0x49 => Opcode::BlobHash,
            0x4a => Opcode::BlobBaseFee,
            0x50 => Opcode::Pop,
            0x51 => Opcode::MLoad,
            0x52 => Opcode::MStore,
            0x53 => Opcode::MStore8,
            0x54 => Opcode::SLoad,
            0x55 => Opcode::SStore,
            0x56 => Opcode::Jump,
            0x57 => Opcode::JumpI,
            0x58 => Opcode::Pc,
            0x59 => Opcode::MSize,
            0x5a => Opcode::Gas,
            0x5b => Opcode::JumpDest,
            0x5c => Opcode::TLoad,
            0x5d => Opcode::TStore,
            0x5e => Opcode::MCopy,
            0x5f => Opcode::Push0,
            0x60..=0x7f => Opcode::Push(b - 0x5f),   // PUSH1=0x60→1, PUSH32=0x7f→32
            0x80..=0x8f => Opcode::Dup(b - 0x7f),    // DUP1=0x80→1, DUP16=0x8f→16
            0x90..=0x9f => Opcode::Swap(b - 0x8f),   // SWAP1=0x90→1, SWAP16=0x9f→16
            0xa0..=0xa4 => Opcode::Log(b - 0xa0),    // LOG0=0xa0→0, LOG4=0xa4→4
            0xf0 => Opcode::Create,
            0xf1 => Opcode::Call,
            0xf2 => Opcode::CallCode,
            0xf3 => Opcode::Return,
            0xf4 => Opcode::DelegateCall,
            0xf5 => Opcode::Create2,
            0xfa => Opcode::StaticCall,
            0xfd => Opcode::Revert,
            0xfe => Opcode::Invalid,
            0xff => Opcode::SelfDestruct,
            other => Opcode::Unknown(other),
        }
    }

    /// Number of bytes of immediate data that follow this opcode in the bytecode.
    pub fn imm_size(&self) -> usize {
        match self {
            Opcode::Push(n) => *n as usize,
            _ => 0,
        }
    }

    /// Items popped from the stack (not applicable to DUP/SWAP which are handled specially).
    pub fn pops(&self) -> usize {
        match self {
            Opcode::Stop | Opcode::Address | Opcode::Origin | Opcode::Caller
            | Opcode::CallValue | Opcode::CallDataSize | Opcode::CodeSize
            | Opcode::GasPrice | Opcode::ReturnDataSize | Opcode::Coinbase
            | Opcode::Timestamp | Opcode::Number | Opcode::Prevrandao
            | Opcode::GasLimit | Opcode::ChainId | Opcode::SelfBalance
            | Opcode::BaseFee | Opcode::BlobBaseFee | Opcode::Pc
            | Opcode::MSize | Opcode::Gas | Opcode::JumpDest
            | Opcode::Push0 | Opcode::Push(_) | Opcode::Invalid => 0,

            Opcode::IsZero | Opcode::Not | Opcode::Balance | Opcode::CallDataLoad
            | Opcode::ExtCodeSize | Opcode::ExtCodeHash | Opcode::BlockHash
            | Opcode::BlobHash | Opcode::Pop | Opcode::MLoad | Opcode::SLoad
            | Opcode::Jump | Opcode::TLoad | Opcode::SelfDestruct => 1,

            Opcode::Add | Opcode::Mul | Opcode::Sub | Opcode::Div | Opcode::SDiv
            | Opcode::Mod | Opcode::SMod | Opcode::Exp | Opcode::SignExtend
            | Opcode::Lt | Opcode::Gt | Opcode::SLt | Opcode::SGt | Opcode::Eq
            | Opcode::And | Opcode::Or | Opcode::Xor | Opcode::Byte
            | Opcode::Shl | Opcode::Shr | Opcode::Sar | Opcode::Sha3
            | Opcode::MStore | Opcode::MStore8 | Opcode::SStore | Opcode::JumpI
            | Opcode::TStore | Opcode::Return | Opcode::Revert => 2,

            Opcode::AddMod | Opcode::MulMod | Opcode::CallDataCopy | Opcode::CodeCopy
            | Opcode::ReturnDataCopy | Opcode::MCopy | Opcode::Create => 3,

            Opcode::ExtCodeCopy | Opcode::Create2 => 4,

            Opcode::Log(n) => 2 + *n as usize,

            Opcode::DelegateCall | Opcode::StaticCall => 6,

            Opcode::Call | Opcode::CallCode => 7,

            // DUP/SWAP handled in the lifter, pops() not used for them
            Opcode::Dup(_) | Opcode::Swap(_) => 0,

            Opcode::Unknown(_) => 0,
        }
    }

    /// Items pushed onto the stack.
    pub fn pushes(&self) -> usize {
        match self {
            // Zero-result instructions
            Opcode::Stop | Opcode::CallDataCopy | Opcode::CodeCopy | Opcode::ExtCodeCopy
            | Opcode::ReturnDataCopy | Opcode::MCopy | Opcode::Pop | Opcode::MStore
            | Opcode::MStore8 | Opcode::SStore | Opcode::Jump | Opcode::JumpDest
            | Opcode::TStore | Opcode::Log(_) | Opcode::Return | Opcode::Revert
            | Opcode::Invalid | Opcode::SelfDestruct | Opcode::JumpI => 0,

            // DUP/SWAP handled specially
            Opcode::Dup(_) | Opcode::Swap(_) => 0,

            // Everything else produces one value
            _ => 1,
        }
    }

    /// True if this instruction ends a basic block.
    pub fn is_terminator(&self) -> bool {
        matches!(
            self,
            Opcode::Jump
                | Opcode::JumpI
                | Opcode::Stop
                | Opcode::Return
                | Opcode::Revert
                | Opcode::Invalid
                | Opcode::SelfDestruct
        )
    }

    /// True if this is an external call that may transfer control.
    pub fn is_call(&self) -> bool {
        matches!(
            self,
            Opcode::Call | Opcode::CallCode | Opcode::DelegateCall | Opcode::StaticCall
        )
    }

    /// True if this writes to persistent storage.
    pub fn is_storage_write(&self) -> bool {
        matches!(self, Opcode::SStore)
    }

    pub fn name(&self) -> String {
        match self {
            Opcode::Stop => "STOP".into(),
            Opcode::Add => "ADD".into(),
            Opcode::Mul => "MUL".into(),
            Opcode::Sub => "SUB".into(),
            Opcode::Div => "DIV".into(),
            Opcode::SDiv => "SDIV".into(),
            Opcode::Mod => "MOD".into(),
            Opcode::SMod => "SMOD".into(),
            Opcode::AddMod => "ADDMOD".into(),
            Opcode::MulMod => "MULMOD".into(),
            Opcode::Exp => "EXP".into(),
            Opcode::SignExtend => "SIGNEXTEND".into(),
            Opcode::Lt => "LT".into(),
            Opcode::Gt => "GT".into(),
            Opcode::SLt => "SLT".into(),
            Opcode::SGt => "SGT".into(),
            Opcode::Eq => "EQ".into(),
            Opcode::IsZero => "ISZERO".into(),
            Opcode::And => "AND".into(),
            Opcode::Or => "OR".into(),
            Opcode::Xor => "XOR".into(),
            Opcode::Not => "NOT".into(),
            Opcode::Byte => "BYTE".into(),
            Opcode::Shl => "SHL".into(),
            Opcode::Shr => "SHR".into(),
            Opcode::Sar => "SAR".into(),
            Opcode::Sha3 => "SHA3".into(),
            Opcode::Address => "ADDRESS".into(),
            Opcode::Balance => "BALANCE".into(),
            Opcode::Origin => "ORIGIN".into(),
            Opcode::Caller => "CALLER".into(),
            Opcode::CallValue => "CALLVALUE".into(),
            Opcode::CallDataLoad => "CALLDATALOAD".into(),
            Opcode::CallDataSize => "CALLDATASIZE".into(),
            Opcode::CallDataCopy => "CALLDATACOPY".into(),
            Opcode::CodeSize => "CODESIZE".into(),
            Opcode::CodeCopy => "CODECOPY".into(),
            Opcode::GasPrice => "GASPRICE".into(),
            Opcode::ExtCodeSize => "EXTCODESIZE".into(),
            Opcode::ExtCodeCopy => "EXTCODECOPY".into(),
            Opcode::ReturnDataSize => "RETURNDATASIZE".into(),
            Opcode::ReturnDataCopy => "RETURNDATACOPY".into(),
            Opcode::ExtCodeHash => "EXTCODEHASH".into(),
            Opcode::BlockHash => "BLOCKHASH".into(),
            Opcode::Coinbase => "COINBASE".into(),
            Opcode::Timestamp => "TIMESTAMP".into(),
            Opcode::Number => "NUMBER".into(),
            Opcode::Prevrandao => "PREVRANDAO".into(),
            Opcode::GasLimit => "GASLIMIT".into(),
            Opcode::ChainId => "CHAINID".into(),
            Opcode::SelfBalance => "SELFBALANCE".into(),
            Opcode::BaseFee => "BASEFEE".into(),
            Opcode::BlobHash => "BLOBHASH".into(),
            Opcode::BlobBaseFee => "BLOBBASEFEE".into(),
            Opcode::Pop => "POP".into(),
            Opcode::MLoad => "MLOAD".into(),
            Opcode::MStore => "MSTORE".into(),
            Opcode::MStore8 => "MSTORE8".into(),
            Opcode::SLoad => "SLOAD".into(),
            Opcode::SStore => "SSTORE".into(),
            Opcode::Jump => "JUMP".into(),
            Opcode::JumpI => "JUMPI".into(),
            Opcode::Pc => "PC".into(),
            Opcode::MSize => "MSIZE".into(),
            Opcode::Gas => "GAS".into(),
            Opcode::JumpDest => "JUMPDEST".into(),
            Opcode::TLoad => "TLOAD".into(),
            Opcode::TStore => "TSTORE".into(),
            Opcode::MCopy => "MCOPY".into(),
            Opcode::Push0 => "PUSH0".into(),
            Opcode::Push(n) => format!("PUSH{}", n),
            Opcode::Dup(n) => format!("DUP{}", n),
            Opcode::Swap(n) => format!("SWAP{}", n),
            Opcode::Log(n) => format!("LOG{}", n),
            Opcode::Create => "CREATE".into(),
            Opcode::Call => "CALL".into(),
            Opcode::CallCode => "CALLCODE".into(),
            Opcode::Return => "RETURN".into(),
            Opcode::DelegateCall => "DELEGATECALL".into(),
            Opcode::Create2 => "CREATE2".into(),
            Opcode::StaticCall => "STATICCALL".into(),
            Opcode::Revert => "REVERT".into(),
            Opcode::Invalid => "INVALID".into(),
            Opcode::SelfDestruct => "SELFDESTRUCT".into(),
            Opcode::Unknown(b) => format!("UNKNOWN(0x{:02x})", b),
        }
    }
}
