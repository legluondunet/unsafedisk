// Read-only interpreter of the two EAX-only unSafeDisc modifier
// functions observed in the owner's Windows 98 memory snapshot.
// No code bytes from the proprietary DLL are embedded here.
//
// Copyright (C) 2026 legluondunet
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This is NOT a SafeDisc unpacker: only a narrow, observed extra
// DWORD layer is modeled. Callers must validate snapshot SHA-256,
// PE geometry, and relevant relocation ranges BEFORE decoding.

pub const FIRST_RVA: usize = 0x65BE;
pub const SECOND_RVA: usize = 0x6621;
pub const END_RVA: usize = 0x6684;
pub const SNAPSHOT_SIZE: usize = 0x29000;
pub const VERIFIED_SNAPSHOT_SHA256: &str =
    "5931af1ba40b0f28b0bb3e9fabc663127bbd9a8c1de8ea1e9c87b56154c84519";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Nop, Inc, Dec, Neg,
    Add(u32), Sub(u32), Xor(u32),
    Rol(u32), Ror(u32),
}

#[derive(Debug, Clone)]
pub struct Modifier {
    ops: Vec<Op>,
}

impl Modifier {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != SECOND_RVA-FIRST_RVA {
            return Err("expected an exactly 99-byte EAX modifier".into());
        }
        let mut ops = Vec::new();
        let mut p = 0usize;
        while p < bytes.len() {
            if bytes[p] == 0xC3 {
                if p+1 != bytes.len() {
                    return Err("RET occurs before the end of the modifier".into());
                }
                return Ok(Self { ops });
            }
            let op = match bytes[p] {
                0x90 => { p+=1; Op::Nop }
                0x40 => { p+=1; Op::Inc }
                0x48 => { p+=1; Op::Dec }
                0xF7 if bytes.get(p+1)==Some(&0xD8) => {
                    p+=2; Op::Neg
                }
                0xC1 => {
                    let kind = *bytes.get(p+1).ok_or("truncated rotate")?;
                    let count = u32::from(*bytes.get(p+2).ok_or("truncated rotate count")?);
                    p+=3;
                    match kind {
                        0xC0 => Op::Rol(count),
                        0xC8 => Op::Ror(count),
                        _ => return Err("non-EAX rotate instruction".into()),
                    }
                }
                0x05|0x2D|0x35 => {
                    let raw = bytes.get(p+1..p+5).ok_or("truncated immediate")?;
                    let imm = u32::from_le_bytes(raw.try_into()
                        .map_err(|_|"invalid immediate width")?);
                    let opcode = bytes[p];
                    p+=5;
                    match opcode {
                        0x05 => Op::Add(imm),
                        0x2D => Op::Sub(imm),
                        _ => Op::Xor(imm),
                    }
                }
                opcode => return Err(format!(
                    "unsupported modifier instruction 0x{opcode:02X} at +0x{p:X}"
                )),
            };
            ops.push(op);
        }
        Err("modifier has no terminal RET".into())
    }

    pub fn operations(&self) -> usize { self.ops.len() }

    pub fn forward(&self, value: u32) -> u32 {
        self.ops.iter().fold(value, |v, op| match *op {
            Op::Nop => v,
            Op::Inc => v.wrapping_add(1),
            Op::Dec => v.wrapping_sub(1),
            Op::Neg => v.wrapping_neg(),
            Op::Add(n) => v.wrapping_add(n),
            Op::Sub(n) => v.wrapping_sub(n),
            Op::Xor(n) => v^n,
            Op::Rol(n) => v.rotate_left(n),
            Op::Ror(n) => v.rotate_right(n),
        })
    }

    pub fn inverse(&self, value: u32) -> u32 {
        self.ops.iter().rev().fold(value, |v, op| match *op {
            Op::Nop => v,
            Op::Inc => v.wrapping_sub(1),
            Op::Dec => v.wrapping_add(1),
            Op::Neg => v.wrapping_neg(),
            Op::Add(n) => v.wrapping_sub(n),
            Op::Sub(n) => v.wrapping_add(n),
            Op::Xor(n) => v^n,
            Op::Rol(n) => v.rotate_right(n),
            Op::Ror(n) => v.rotate_left(n),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Pair {
    pub first: Modifier,
    pub second: Modifier,
}

impl Pair {
    /// Input must be a complete, RVA-addressed *mapped* PE image.
    /// This decoder does not by itself establish that the image is
    /// the verified capture; use a strict SHA/geometry gate.
    pub fn from_mapped_image(image: &[u8]) -> Result<Self,String> {
        let first = image.get(FIRST_RVA..SECOND_RVA)
            .ok_or("first modifier not mapped")?;
        let second = image.get(SECOND_RVA..END_RVA)
            .ok_or("second modifier not mapped")?;
        Ok(Self {
            first: Modifier::decode(first)?,
            second: Modifier::decode(second)?,
        })
    }

    /// Reconstructed, bounded EAX-only arithmetic for the verified Crimson
    /// 1.0.2.0 modifier pair. This contains *operations and constants*, not
    /// proprietary DLL machine-code bytes or any mapped Win98 memory image.
    /// Both exact Crimson versions have independently matched these stages.
    pub fn crimson_static() -> Self {
        use Op::*;
        let first=Modifier{ops:vec![
            Nop,Ror(130),Add(0x07a8510f),Add(0x12c60fdd),
            Add(0x5988263e),Xor(0x0f716218),Ror(96),Add(0x5d5b4dff),
            Rol(160),Rol(83),Sub(0x78091744),Rol(177),Rol(128),
            Sub(0x5644466d),Sub(0x20d25f2d),Ror(100),
            Xor(0x65467529),Ror(204),Xor(0x536c74d1),
            Xor(0x00ed7185),Add(0x74611839),Xor(0x22cc5dad),
            Sub(0x607a2148),Rol(203),
        ]};
        let second=Modifier{ops:vec![
            Add(0x211e0b7f),Add(0x0c633d1c),Sub(0x05cd18ac),
            Ror(61),Rol(226),Rol(147),Rol(32),Dec,Rol(155),Dec,
            Ror(138),Ror(142),Inc,Rol(80),Add(0x5988263e),Inc,
            Xor(0x09f36160),Rol(255),Inc,Sub(0x03f05a53),
            Neg,Ror(227),Xor(0x105f5644),Xor(0x6e3a20d2),
            Dec,Inc,Xor(0x1faa478b),Xor(0x00ed7185),
            Inc,Dec,Rol(5),Rol(251),Inc,
        ]};
        Self{first,second}
    }
    /// When the user still provides a historical Win98 capture, require
    /// the original arithmetic operation sequence to be *identical*
    /// to the snapshot-free implementation, rather than comparing only
    /// several synthetic probe inputs.
    pub fn matches_static_sequence(&self)->bool {
        let reference=Self::crimson_static();
        self.first.ops==reference.first.ops && self.second.ops==reference.second.ops
    }

    pub fn index_mask(i:u32) -> u32 {
        (i<<24)|(i<<16)|(i<<8)|i
    }

    /// Historical 0x401F62 loop; conditional on EDX and ECX
    /// preservation by the two observed EAX-only functions.
    pub fn extra_word(&self, value:u32, index:u32) -> u32 {
        let m=Self::index_mask(index);
        self.second.forward(self.first.forward(value^m)^m)
    }

    pub fn inverse_extra_word(&self, value:u32, index:u32) -> u32 {
        let m=Self::index_mask(index);
        self.first.inverse(self.second.inverse(value)^m)^m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crimson_arithmetic_matches_verified_win98_vectors() {
        let pair=Pair::crimson_static();
        assert_eq!(pair.first.operations(),24);
        assert_eq!(pair.second.operations(),33);
        for (input,f1,f2,extra0,extra256) in [
            (0u32,0x8BD9_668C,0xF01C_8BF1,0xC293_E587,0x32A3_7588),
            (1,0x2BD9_668D,0xF01C_8E71,0xC293_E437,0x32A3_7438),
            (0x1234_5678,0x514D_C13F,0x160B_DBAC,0x8B7C_2B0C,0x38CC_BB0D),
            (0xDEAD_BEEF,0x57C4_CE69,0x58BF_1342,0xDCC4_420D,0x4E37_520E),
            (u32::MAX,0x0BD9_668D,0xF01C_8B71,0xC293_E447,0x55C3_5448),
        ]{
            assert_eq!(pair.first.forward(input),f1);
            assert_eq!(pair.second.forward(input),f2);
            assert_eq!(pair.extra_word(input,0),extra0);
            assert_eq!(pair.extra_word(input,256),extra256);
            assert_eq!(pair.inverse_extra_word(extra0,0),input);
            assert_eq!(pair.inverse_extra_word(extra256,256),input);
        }
        assert!(pair.matches_static_sequence());
    }

    fn toy_pair() -> Pair {
        let mut image=vec![0u8;END_RVA];
        image[FIRST_RVA..SECOND_RVA-1].fill(0x40);
        image[SECOND_RVA-1]=0xC3;
        image[SECOND_RVA..END_RVA-1].fill(0x48);
        image[END_RVA-1]=0xC3;
        Pair::from_mapped_image(&image).unwrap()
    }

    #[test]
    fn strict_decoder_rejects_illegal_or_truncated() {
        for bad in [0x00u8,0x8B,0xE8,0xFF] {
            let mut data=vec![0x90;99];
            data[7]=bad;
            data[98]=0xC3;
            assert!(Modifier::decode(&data).is_err());
        }
        let mut data=vec![0x90;99];
        data[1]=0xC3; data[98]=0xC3;
        assert!(Modifier::decode(&data).is_err());
        assert!(Modifier::decode(&[0xC3]).is_err());
        data[1]=0x90;
        data[98]=0xC1; // truncated rotation
        assert!(Modifier::decode(&data).is_err());
    }

    #[test]
    fn synthetic_pair_is_reversible() {
        let pair=toy_pair();
        assert_eq!(pair.first.operations(),98);
        assert_eq!(pair.second.operations(),98);
        for src in [0,1,0x12345678,u32::MAX] {
            for i in [0,1,255,256,257,0xABCD1234,u32::MAX] {
                let encoded=pair.extra_word(src,i);
                assert_eq!(pair.inverse_extra_word(encoded,i),src);
            }
        }
    }

    #[test]
    fn x86_full_width_mask_not_byte_truncated() {
        assert_eq!(Pair::index_mask(255),0xFFFFFFFF);
        assert_eq!(Pair::index_mask(256),0x01010100);
        assert_eq!(Pair::index_mask(257),0x01010101);
        assert_eq!(Pair::index_mask(1),Pair::index_mask(257));
    }

    #[test]
    fn rotation_count_uses_low_five_bits() {
        let mut bytes=vec![0x90;99];
        bytes[0]=0xC1;bytes[1]=0xC0;bytes[2]=0xA3;
        bytes[98]=0xC3;
        let decoded=Modifier::decode(&bytes).unwrap();
        assert_eq!(decoded.forward(1),1u32.rotate_left(3));
        assert_eq!(decoded.inverse(decoded.forward(0x12345678)),0x12345678);
    }

    #[test]
    fn fails_closed_on_missing_mapped_rva_region() {
        assert!(Pair::from_mapped_image(&[0u8;1024]).is_err());
    }
}
