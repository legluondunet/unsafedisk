// Verified SafeDisc import-name decoder for the owner's exact French Crimson Skies ICD.
// Research-only: reconstructs names in memory, never writes game binaries.
// SPDX-License-Identifier: GPL-3.0-or-later

pub const FRENCH_ICD_SHA: &str = "f3fe7c1ee6f62be1c9fa216ad90b57cc3653d2673095704bf439d1592e7262eb";
// PE RVAs of three contiguous encoded import-name record regions, independently
// verified against the unSafeDisc 1.5.5 Windows 98 TESTME.EXE output.
const ENCODED_RANGES: [(u32,u32);3] = [
    (0x0062_0E24,0x0062_12E2), // 70 KERNEL32 names
    (0x0062_12F0,0x0062_16CE), // 62 USER32 names
    (0x0062_24C2,0x0062_2526), // 4 extra KERNEL32 names
];

#[derive(Debug)]
pub struct ImportDecodeReport {
    pub reconstructed: Vec<u8>, // .idata only; not a runnable executable
    pub names: usize,
    pub changed_bytes: usize,
    pub total_record_bytes: usize,
}

fn decode_record_with_seed(input: &[u8], seed:u8) -> Result<Vec<u8>,String> {
    if input.len()<5 {return Err("import record too short".into());}
    let length=input[0] as usize;
    if length<2 || length>128 || input.len()!=length+2 {
        return Err("invalid encoded import-name length".into());
    }
    let mut out=vec![0u8;input.len()];
    let mut previous=seed;
    for i in 0..length {
        let current=input[i+2];
        out[i+2]=current^previous;
        previous=current;
    }
    if out[2]^0x3D != input[1] || out[input.len()-1]!=0 ||
        !out[2..input.len()-1].iter().all(u8::is_ascii_graphic) {
        return Err("invalid encoded import-name header or bytes".into());
    }
    Ok(out)
}

fn decode_record(input:&[u8])->Result<Vec<u8>,String>{
    decode_record_with_seed(input,0xC1)
}

pub fn restore_import_names(
    original:&[u8], section_rva:u32, raw_start:usize, raw_len:usize,
)->Result<ImportDecodeReport,String> {
    restore_import_names_with_seed(original,section_rva,raw_start,raw_len,0xC1)
}

/// In the verified original retail edition the initial cipher byte is 0xDF;
/// the French edition uses 0xC1. All other record layout checks are shared.
pub fn restore_import_names_with_seed(
    original:&[u8], section_rva:u32, raw_start:usize, raw_len:usize,seed:u8,
)->Result<ImportDecodeReport,String> {
    if !matches!(seed,0xC1|0xDF){return Err("unsupported import cipher seed".into());}
    let end=raw_start.checked_add(raw_len).ok_or("section extent overflow")?;
    let mut out=original.get(raw_start..end)
        .ok_or("section extends beyond file")?.to_vec();
    let mut total_names=0usize;
    let mut changed=0usize;
    let mut total_bytes=0usize;
    for (lo,hi) in ENCODED_RANGES {
        let start=lo.checked_sub(section_rva).ok_or("encoded region before .idata")? as usize;
        let stop=hi.checked_sub(section_rva).ok_or("encoded region before .idata")? as usize;
        if start>=stop || stop>out.len() {return Err("encoded region outside .idata".into());}
        let mut pos=start;
        while pos<stop {
            let len=out[pos] as usize;
            let record_end=pos.checked_add(2).and_then(|x|x.checked_add(len))
                .ok_or("import record length overflow")?;
            if record_end>stop {return Err("import record extends beyond range".into());}
            let decoded=decode_record_with_seed(&out[pos..record_end],seed)?;
            changed+=out[pos..record_end].iter().zip(decoded.iter())
                .filter(|(x,y)|x!=y).count();
            total_bytes+=decoded.len();
            out[pos..record_end].copy_from_slice(&decoded);
            pos=record_end + (len & 1);
            total_names+=1;
        }
        if pos!=stop {return Err("misaligned encoded import-name range".into());}
    }
    if total_names!=136 || changed!=2234 || total_bytes!=2234 {
        return Err(format!("unexpected reconstruction result: names={total_names}, changed={changed}, bytes={total_bytes}"));
    }
    Ok(ImportDecodeReport{
        reconstructed:out,names:total_names,changed_bytes:changed,total_record_bytes:total_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encode(name:&str)->Vec<u8> {
        let mut c=vec![(name.len()+1) as u8,(name.as_bytes()[0]^0x3D)];
        let mut last=0xC1u8;
        for &plain in name.as_bytes().iter().chain(std::iter::once(&0)) {
            let cipher=plain^last;
            c.push(cipher);
            last=cipher;
        }
        c
    }
    #[test]
    fn decode_known_name(){
        let raw=encode("lstrcmpA");
        assert_eq!(raw,vec![0x09,0x51,0xAD,0xDE,0xAA,0xD8,0xBB,0xD6,0xA6,0xE7,0xE7]);
        assert_eq!(decode_record(&raw).unwrap(),b"\0\0lstrcmpA\0");
    }
    #[test]
    fn decode_name_roundtrips(){
        for name in ["RegisterWindowMessageA","LoadBitmapA","InitializeCriticalSection"] {
            let raw=encode(name);
            let mut expected=vec![0u8;2];
            expected.extend_from_slice(name.as_bytes());
            expected.push(0);
            assert_eq!(decode_record(&raw).unwrap(),expected);
        }
    }
    #[test]
    fn original_edition_seed_roundtrip(){
        let raw=vec![0x09,0x51,0xB3,0xC0,0xB4,0xC6,0xA5,0xC8,0xB8,0xF9,0xF9];
        assert_eq!(decode_record_with_seed(&raw,0xDF).unwrap(),b"\0\0lstrcmpA\0");
        assert!(decode_record_with_seed(&raw,0xC1).is_err());
    }
    #[test]
    fn reject_corruption(){
        let mut raw=encode("lstrcmpA");
        raw[1]^=1;
        assert!(decode_record(&raw).is_err());
    }
}
