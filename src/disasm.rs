use crate::opcodes::Opcode;

/// A single decoded EVM instruction.
#[derive(Debug, Clone)]
pub struct RawInsn {
    pub pc:  usize,
    pub op:  Opcode,
    pub imm: Vec<u8>,   // immediate bytes (non-empty only for PUSH1..PUSH32)
}

impl RawInsn {
    /// If this is a PUSH with a concrete target that fits in a usize, return it.
    pub fn push_target(&self) -> Option<usize> {
        if self.imm.is_empty() {
            return None;
        }
        if self.imm.len() > 8 {
            return None; // would overflow usize on 64-bit
        }
        let mut buf = [0u8; 8];
        let off = 8 - self.imm.len();
        buf[off..].copy_from_slice(&self.imm);
        Some(usize::from_be_bytes(buf))
    }
}

/// Disassemble raw bytecode into a list of instructions.
///
/// Strips optional Solidity CBOR metadata from the tail first.
pub fn disassemble(raw: &[u8]) -> Vec<RawInsn> {
    let code = strip_metadata(raw);
    let mut insns = Vec::new();
    let mut pc = 0usize;

    while pc < code.len() {
        let byte = code[pc];
        let op   = Opcode::from_byte(byte);
        let n    = op.imm_size();

        let imm = if n > 0 && pc + 1 + n <= code.len() {
            code[pc + 1..pc + 1 + n].to_vec()
        } else if n > 0 {
            // Truncated at end — pad with zeros
            let mut v = vec![0u8; n];
            let avail = code.len() - (pc + 1);
            v[..avail].copy_from_slice(&code[pc + 1..]);
            v
        } else {
            vec![]
        };

        insns.push(RawInsn { pc, op, imm });
        pc += 1 + n;
    }
    insns
}

/// Parse input that may be raw bytes or an ASCII hex string (with or without 0x prefix).
pub fn parse_input(data: &[u8]) -> Vec<u8> {
    // If printable ASCII (hex string), decode it
    if data.iter().all(|&b| b.is_ascii_hexdigit() || b == b'\n' || b == b'\r' || b == b' ') {
        let hex: String = data
            .iter()
            .filter(|&&b| b.is_ascii_hexdigit())
            .map(|&b| b as char)
            .collect();
        let hex = hex.trim_start_matches("0x");
        if hex.len() % 2 == 0 {
            if let Ok(decoded) = hex_decode(hex) {
                return decoded;
            }
        }
    }
    data.to_vec()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// Strip Solidity / Vyper CBOR metadata appended to the end of bytecode.
///
/// The last two bytes encode the length of the metadata block.
/// If the inferred start byte looks like a CBOR map header, drop the block.
fn strip_metadata(code: &[u8]) -> &[u8] {
    if code.len() < 4 {
        return code;
    }
    let n = code.len();
    let len = u16::from_be_bytes([code[n - 2], code[n - 1]]) as usize;

    // Sanity: metadata must fit and be non-trivially sized
    if len == 0 || len + 2 > n || len * 2 > n {
        return code;
    }

    let meta_start = n - 2 - len;
    // CBOR map headers: 0xa0–0xbf
    if code[meta_start] >= 0xa0 && code[meta_start] <= 0xbf {
        return &code[..meta_start];
    }
    code
}
