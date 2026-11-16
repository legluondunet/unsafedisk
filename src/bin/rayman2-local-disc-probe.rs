// Rayman 2: experimental local-CD file route on an exact retail executable.
// Copyright (C) 2026 legluondunet
// SPDX-License-Identifier: GPL-3.0-or-later
// Only a NEW output file is created. No GOG bytes, proprietary samples, or
// game runtime are embedded. This is NOT a verified SafeDisc decryptor.
#[allow(dead_code)]
#[path = "rayman2-inspect.rs"]
mod inspect;

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process;

type Result<T> = std::result::Result<T, String>;
const ORIGINAL_SHA: &str = "7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3";
const PE32_SHA: &str = "f32133d9add18b37adf47ce4b3e475b641b697e2b7db77cfe7b47063da468703";
const SOURCE_LEN: usize = 676_352;
const SCANNER_VA: u32 = 0x0044_7C20;
const VOLUME_VA: u32 = 0x0044_8E5A;
const DRIVE_FORMATS: [u32;5] = [0x49F394, 0x49F3A4, 0x4A06D8, 0x4A2264, 0x4A2688];
const SCANNER_OLD: [u8;25] = [
    0x83,0xC1,0x18,0x85,0xC9,0x74,0x50,0x8B,0x49,0x60,0x85,0xC9,0x74,0x49,0x03,
    0xCA,0x85,0xC9,0x74,0x43,0x8B,0x49,0x0C,0x03,0xCA
];
const SCANNER_FIXED: [u8;25] = [
    0x83,0xC1,0x18,0x66,0x81,0x39,0x0B,0x01,0x75,0x4D,0x8B,0x49,0x60,0x85,0xC9,
    0x74,0x46,0x03,0xCA,0x8B,0x49,0x0C,0x03,0xCA,0x90
];
const VOLUME_OLD: [u8;11] = [0x8B,0x0D,0xF0,0x0B,0x51,0x00,0xB8,0x5F,0x0B,0x4E,0x83];
// On the original guard-zero path at 0x448E5A:
// MOV AL,'R'; MOV [0x004A6AD8],AL; MOV ESP,EBP; POP EBP; RET.
// Unlike V1, no original DAT selection or file-reading instructions change.
const VOLUME_R: [u8;11] = [0xB0,0x52,0xA2,0xD8,0x6A,0x4A,0x00,0x8B,0xE5,0x5D,0xC3];

fn u16_at(data: &[u8], at: usize) -> Result<u16> {
    let slice=data.get(at..at.checked_add(2).ok_or("u16 offset overflow")?)
        .ok_or("truncated PE u16")?;
    Ok(u16::from_le_bytes([slice[0],slice[1]]))
}
fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    let slice=data.get(at..at.checked_add(4).ok_or("u32 offset overflow")?)
        .ok_or("truncated PE u32")?;
    Ok(u32::from_le_bytes([slice[0],slice[1],slice[2],slice[3]]))
}

#[derive(Debug)]
struct Section { name: [u8;8], rva: u32, virtual_size: u32, raw_len: usize, raw_at: usize, flags: u32 }
struct Image { base: u32, sections: Vec<Section> }

impl Image {
    fn file_offset(&self, data: &[u8], va: u32, len: usize, name: &[u8]) -> Result<usize> {
        if len==0 { return Err("empty PE read request".into()); }
        let section=self.sections.iter().find(|s|s.name.split(|&b|b==0).next()==Some(name))
            .ok_or_else(||"missing PE section".to_owned())?;
        if name==b".text" && (section.flags & 0x2000_0000)==0 {
            return Err("expected executable .text section".into());
        }
        let rva=va.checked_sub(self.base).ok_or("VA below image base")?;
        let rel=rva.checked_sub(section.rva).ok_or("VA below PE section")? as usize;
        let backed=section.raw_len.min(section.virtual_size as usize);
        if !rel.checked_add(len).is_some_and(|end|end<=backed) {
            return Err(format!("VA 0x{va:08X} not backed in expected PE section"));
        }
        let at=section.raw_at.checked_add(rel).ok_or("PE raw offset overflow")?;
        if data.get(at..at.checked_add(len).ok_or("file extent overflow")?).is_none(){
            return Err("requested VA not within source file".into());
        }
        Ok(at)
    }
    fn expect(&self, data:&[u8], va:u32, bytes:&[u8], name:&[u8])->Result<usize>{
        let at=self.file_offset(data,va,bytes.len(),name)?;
        if data.get(at..at+bytes.len())!=Some(bytes){
            return Err(format!("original opcode/data anchor differs at VA 0x{va:08X}"));
        }
        Ok(at)
    }
    fn section(&self,name:&[u8])->Result<&Section>{
        self.sections.iter().find(|s|s.name.split(|&b|b==0).next()==Some(name))
            .ok_or_else(||"missing PE section".to_owned())
    }
}
fn parse_image(data:&[u8])->Result<Image>{
    if data.len()!=SOURCE_LEN || data.get(..2)!=Some(b"MZ"){
        return Err("input is not the pinned 676352-byte MZ image".into());
    }
    let nt=u32_at(data,0x3C)? as usize;
    if data.get(nt..nt.checked_add(4).ok_or("NT overflow")?)!=Some(b"PE\0\0"){
        return Err("invalid PE signature".into());
    }
    let opt=nt.checked_add(24).ok_or("PE optional header overflow")?;
    let opt_size=u16_at(data,nt+20)? as usize;
    if u16_at(data,nt+4)?!=0x14C || u16_at(data,nt+6)?!=3 ||
        opt_size<0xE0 || data.get(opt..opt.checked_add(opt_size).ok_or("optional overflow")?).is_none() ||
        u16_at(data,opt)?!=0x10B {
        return Err("unexpected machine, section count or PE32 header".into());
    }
    let base=u32_at(data,opt+28)?;
    let entry=u32_at(data,opt+16)?;
    if base!=0x400000 || entry!=0x5FCC0 {
        return Err("unexpected image base/entrypoint".into());
    }
    let table=opt.checked_add(opt_size).ok_or("PE section table overflow")?;
    let mut sections=Vec::new();
    for i in 0..3usize{
        let at=table.checked_add(i*40).ok_or("PE section offset overflow")?;
        let row=data.get(at..at+40).ok_or("truncated section header")?;
        let mut name=[0u8;8]; name.copy_from_slice(&row[..8]);
        let s=Section{
            name,
            virtual_size:u32_at(data,at+8)?,
            rva:u32_at(data,at+12)?,
            raw_len:u32_at(data,at+16)? as usize,
            raw_at:u32_at(data,at+20)? as usize,
            flags:u32_at(data,at+36)?,
        };
        if data.get(s.raw_at..s.raw_at.checked_add(s.raw_len).ok_or("raw length overflow")?).is_none(){
            return Err("PE section exceeds file".into());
        }
        sections.push(s);
    }
    let image=Image{base,sections};
    for name in [b".text".as_slice(),b".rdata".as_slice(),b".data".as_slice()]{
        if image.sections.iter().filter(|s|s.name.split(|&b|b==0).next()==Some(name)).count()!=1{
            return Err("unexpected PE section set".into());
        }
    }
    Ok(image)
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Mode { RelativeFolder, WineDrive }
impl Mode {
    fn from_str(value:&str)->Result<Self>{
        match value {
            "relative-folder"=>Ok(Self::RelativeFolder),
            "wine-drive"=>Ok(Self::WineDrive),
            _=>Err("mode must be relative-folder or wine-drive".into()),
        }
    }
    fn label(self)->&'static str{
        match self {
            Self::RelativeFolder=>"relative R directory (no Wine drive mapping)",
            Self::WineDrive=>"Wine/Windows R: mapped drive (no relative-path changes)",
        }
    }
}

fn create_candidate(data:&[u8], scanner_fixed:bool, mode:Mode)->Result<(Vec<u8>,usize)> {
    let pe=parse_image(data)?;
    let at_scan=pe.expect(data,SCANNER_VA,
        if scanner_fixed {&SCANNER_FIXED} else {&SCANNER_OLD}, b".text")?;
    let at_cd=pe.expect(data,VOLUME_VA,&VOLUME_OLD,b".text")?;
    // Context and original x86 stack-frame restore must be what we expect.
    pe.expect(data,0x448E30,&[0x55,0x8B,0xEC,0x81,0xEC,0xEC,0,0,0,
        0xA1,0xEC,0x13,0x51,0,0x85,0xC0,0x74],b".text")?;
    pe.expect(data,0x448E56,&[0x8B,0xE5,0x5D,0xC3],b".text")?;
    let mut at_formats=Vec::new();
    for va in DRIVE_FORMATS {
        let at=pe.expect(data,va,b"%c:\\",b".data")?;
        at_formats.push(at+2);
    }
    // Reject editions with a sixth unhandled drive-format string.
    let ds=pe.section(b".data")?;
    let actual=data[ds.raw_at..ds.raw_at+ds.raw_len].windows(4)
        .enumerate().filter_map(|(i,w)|if w==b"%c:\\" {Some(ds.raw_at+i+2)} else {None})
        .collect::<Vec<_>>();
    if actual!=at_formats {
        return Err("unexpected original drive-format census/order".into());
    }
    let mut output=data.to_vec();
    if !scanner_fixed {
        output[at_scan..at_scan+SCANNER_FIXED.len()].copy_from_slice(&SCANNER_FIXED);
    }
    output[at_cd..at_cd+VOLUME_R.len()].copy_from_slice(&VOLUME_R);
    if mode==Mode::RelativeFolder {
        for at in &at_formats {output[*at]=b'\\';}
    }
    let mut n_changed=0usize;
    for (i,(old,new)) in data.iter().zip(&output).enumerate() {
        if old!=new {
            n_changed+=1;
            if ((!scanner_fixed)&&(at_scan..at_scan+25).contains(&i)) ||
                (at_cd..at_cd+11).contains(&i) ||
                (mode==Mode::RelativeFolder && at_formats.contains(&i)) {continue;}
            return Err("internal error: unexpected byte outside allowlisted sites".into());
        }
    }
    if n_changed==0||n_changed>41 { return Err("unexpected candidate delta".into()); }
    Ok((output,n_changed))
}
fn help(){
    println!("rayman2-local-disc-probe: exact-owner-CD experimental local resource routing\n\
Usage:\n\
  rayman2-local-disc-probe --source ORIGINAL.exe --output NEW.exe \\\n\
     --mode relative-folder [--dry-run]\n\
  rayman2-local-disc-probe --source ORIGINAL.exe --output NEW.exe \\\n\
     --mode wine-drive [--dry-run]\n\
\n\
relative-folder: keep original DAT resource parser; resolve R\\Data\\... via an\n\
                 R subfolder/symlink in the game working directory.\n\
wine-drive: original R:\\Data\\... syntax; requires a Wine/Windows R: mapping\n\
            to a directory containing the original CD's extracted files.\n\
Input must match the owner original CD SHA-256 or its PE32-scanner-only copy.\n\
This bypasses ONLY the initial logical CD label/type selection and fixes the\n\
PE32-only module scanner; it does not decrypt SafeDisc or guarantee playability.\n\
A physical CD is not required for the test IF the necessary disc files were\n\
already lawfully extracted. No third-party executable is embedded.");
}
fn run()->Result<()>{
    let mut source:Option<PathBuf>=None;
    let mut output:Option<PathBuf>=None;
    let mut mode:Option<Mode>=None;
    let mut dry_run=false;
    let mut args=env::args().skip(1);
    while let Some(flag)=args.next() {
        if flag=="--help"||flag=="-h"{help();return Ok(());}
        if flag=="--dry-run" {
            if dry_run {return Err("duplicate --dry-run".into());}
            dry_run=true;continue;
        }
        let value=args.next().ok_or_else(||format!("missing argument for {flag}"))?;
        match flag.as_str() {
            "--source" if source.is_none()=>source=Some(PathBuf::from(value)),
            "--output" if output.is_none()=>output=Some(PathBuf::from(value)),
            "--mode" if mode.is_none()=>mode=Some(Mode::from_str(&value)?),
            _=>return Err(format!("unknown or repeated argument {flag}")),
        }
    }
    let input=source.ok_or("missing --source")?;
    let dest=output.ok_or("missing --output")?;
    let mode=mode.ok_or("missing --mode")?;
    let stat=fs::symlink_metadata(&input).map_err(|e|format!("input: {e}"))?;
    if !stat.file_type().is_file() || stat.len()!=SOURCE_LEN as u64 {
        return Err("source must be a regular, non-symlink 676352-byte executable".into());
    }
    if fs::symlink_metadata(&dest).is_ok(){
        return Err("refusing to overwrite existing output or symlink".into());
    }
    let data=fs::read(&input).map_err(|e|format!("reading source: {e}"))?;
    if data.len()!=SOURCE_LEN {return Err("source file changed during read".into());}
    let hash=inspect::sha256(&data);
    let scanner_fixed=match hash.as_str(){
        ORIGINAL_SHA=>false,
        PE32_SHA=>true,
        _=>return Err(format!("unsupported original SHA-256 {hash}")),
    };
    let (candidate,changed)=create_candidate(&data,scanner_fixed,mode)?;
    println!("Verified source SHA-256 {hash}");
    println!("Mode: {}",mode.label());
    println!("Candidate changed {changed} bytes; all original DAT selection/readers preserved.");
    println!("Candidate SHA-256 {}",inspect::sha256(&candidate));
    if dry_run {
        println!("DRY RUN: no file written");
        return Ok(());
    }
    let mut file=OpenOptions::new().write(true).create_new(true).open(&dest)
        .map_err(|e|format!("could not create NEW file: {e}"))?;
    if let Err(e)=file.write_all(&candidate).and_then(|_|file.flush()){
        let _=fs::remove_file(&dest);
        return Err(format!("writing output failed: {e}"));
    }
    println!("Written only NEW candidate {}",dest.display());
    println!("Prototype, not a verified SafeDisc unwrapping. Original input unchanged.");
    Ok(())
}
fn main(){
    if let Err(e)=run(){eprintln!("ERROR: {e}");process::exit(1);}
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture()->Vec<u8>{
        let mut d=vec![0u8;SOURCE_LEN];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&0xe0u32.to_le_bytes());
        d[0xe0..0xe4].copy_from_slice(b"PE\0\0");
        d[0xe4..0xe6].copy_from_slice(&0x14cu16.to_le_bytes());
        d[0xe6..0xe8].copy_from_slice(&3u16.to_le_bytes());
        d[0xf4..0xf6].copy_from_slice(&0xe0u16.to_le_bytes());
        let opt=0xf8;
        d[opt..opt+2].copy_from_slice(&0x10bu16.to_le_bytes());
        d[opt+16..opt+20].copy_from_slice(&0x5fcc0u32.to_le_bytes());
        d[opt+28..opt+32].copy_from_slice(&0x400000u32.to_le_bytes());
        for (i,(name,rva,raw,size,vsize,flags)) in [
            (b".text".as_slice(),0x1000u32,0x400usize,0x9A200usize,0x9A200u32,0x60000020u32),
            (b".rdata".as_slice(),0x9C000,0x9A600,0x3000,0x3000,0x40000040),
            (b".data".as_slice(),0x9F000,0x9D600,0x7C00,0x776D0,0xC0000040),
        ].iter().enumerate(){
            let at=0x1D8+i*40;
            d[at..at+name.len()].copy_from_slice(name);
            d[at+8..at+12].copy_from_slice(&vsize.to_le_bytes());
            d[at+12..at+16].copy_from_slice(&rva.to_le_bytes());
            d[at+16..at+20].copy_from_slice(&(*size as u32).to_le_bytes());
            d[at+20..at+24].copy_from_slice(&(*raw as u32).to_le_bytes());
            d[at+36..at+40].copy_from_slice(&flags.to_le_bytes());
        }
        let pe=parse_image(&d).unwrap();
        for (va,pattern) in [
            (SCANNER_VA,SCANNER_OLD.as_slice()),
            (VOLUME_VA,VOLUME_OLD.as_slice()),
            (0x448E30,&[0x55,0x8B,0xEC,0x81,0xEC,0xEC,0,0,0,
                0xA1,0xEC,0x13,0x51,0,0x85,0xC0,0x74][..]),
            (0x448E56,&[0x8B,0xE5,0x5D,0xC3][..])
        ] {
            let at=pe.file_offset(&d,va,pattern.len(),b".text").unwrap();
            d[at..at+pattern.len()].copy_from_slice(pattern);
        }
        for va in DRIVE_FORMATS {
            let at=pe.file_offset(&d,va,4,b".data").unwrap();
            d[at..at+4].copy_from_slice(b"%c:\\");
        }
        d
    }
    #[test]
    fn known_sha_vectors(){
        assert_eq!(inspect::sha256(b"abc"),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
    #[test]
    fn relative_folder_prototype(){
        let original=fixture();
        let (out,changed)=create_candidate(&original,false,Mode::RelativeFolder).unwrap();
        assert!(changed>0 && changed<=41);
        let pe=parse_image(&out).unwrap();
        let at=pe.file_offset(&out,VOLUME_VA,11,b".text").unwrap();
        assert_eq!(&out[at..at+11],VOLUME_R.as_slice());
        for va in DRIVE_FORMATS {
            let p=pe.file_offset(&out,va,4,b".data").unwrap();
            assert_eq!(&out[p..p+4],b"%c\\\\");
        }
    }
    #[test]
    fn wine_drive_variant_preserves_original_formatting(){
        let source=fixture();
        let (out,changed)=create_candidate(&source,false,Mode::WineDrive).unwrap();
        assert!(changed>0 && changed<=36);
        let pe=parse_image(&out).unwrap();
        for va in DRIVE_FORMATS {
            let p=pe.file_offset(&out,va,4,b".data").unwrap();
            assert_eq!(&out[p..p+4],b"%c:\\");
        }
    }
    #[test]
    fn pe32_only_source_is_accepted_without_overwriting_scanner(){
        let mut d=fixture();
        let pe=parse_image(&d).unwrap();
        let at=pe.file_offset(&d,SCANNER_VA,25,b".text").unwrap();
        d[at..at+25].copy_from_slice(&SCANNER_FIXED);
        let (out,_) = create_candidate(&d,true,Mode::RelativeFolder).unwrap();
        assert_eq!(&out[at..at+25],SCANNER_FIXED.as_slice());
    }
    #[test]
    fn mutated_guard_is_rejected(){
        let mut d=fixture();
        let pe=parse_image(&d).unwrap();
        let at=pe.file_offset(&d,0x448E30,17,b".text").unwrap();
        d[at]^=1;
        assert!(create_candidate(&d,false,Mode::RelativeFolder).is_err());
    }
    #[test]
    fn extra_drive_formatter_is_rejected(){
        let mut d=fixture();
        let pe=parse_image(&d).unwrap();
        let at=pe.file_offset(&d,0x4A2900,4,b".data").unwrap();
        d[at..at+4].copy_from_slice(b"%c:\\");
        assert!(create_candidate(&d,false,Mode::RelativeFolder).is_err());
    }
    #[test]
    fn invalid_section_bounds_are_rejected(){
        let mut d=fixture();
        let at=0x1D8+20;
        d[at..at+4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(parse_image(&d).is_err());
    }
}
