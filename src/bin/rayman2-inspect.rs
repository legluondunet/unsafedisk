// Rayman 2 CD/GOG and SafeDisc auxiliary file inspector.
// Copyright (C) 2026 legluondunet
// SPDX-License-Identifier: GPL-3.0-or-later
// SHA-pinned, read-only, synthetic tests: no game content is distributed.
use std::{env,fs,path::{Path,PathBuf},process};
type Result<T> = std::result::Result<T,String>;
const CD_SHA:&str="7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3";
const GOG_SHA:&str="9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713";
const ICD_SHA:&str="4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6";
const CD_LEN:usize=676_352;
const GOG_LEN:usize=1_468_928;
const ICD_LEN:usize=683_565;
const TEXT_RVA:u32=0x1000;
const TEXT_LEN:usize=0x9A200;
const COPY_RVA:u32=0x118000;

pub(super) fn sha256(input:&[u8])->String{
    const K:[u32;64]=[
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];
    let mut h=[0x6a09e667u32,0xbb67ae85,0x3c6ef372,0xa54ff53a,
               0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    let mut msg=Vec::with_capacity(input.len()+72);
    msg.extend_from_slice(input);
    msg.push(0x80);
    while msg.len()%64!=56{msg.push(0);}
    msg.extend_from_slice(&((input.len() as u64)*8).to_be_bytes());
    for block in msg.chunks_exact(64){
        let mut w=[0u32;64];
        for i in 0..16{w[i]=u32::from_be_bytes(block[4*i..4*i+4].try_into().unwrap());}
        for i in 16..64{
            let x=w[i-15];let y=w[i-2];
            w[i]=w[i-16].wrapping_add(x.rotate_right(7)^x.rotate_right(18)^(x>>3))
                .wrapping_add(w[i-7])
                .wrapping_add(y.rotate_right(17)^y.rotate_right(19)^(y>>10));
        }
        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut z]=h;
        for i in 0..64{
            let s1=e.rotate_right(6)^e.rotate_right(11)^e.rotate_right(25);
            let ch=(e&f)^((!e)&g);
            let t1=z.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0=a.rotate_right(2)^a.rotate_right(13)^a.rotate_right(22);
            let maj=(a&b)^(a&c)^(b&c);
            let t2=s0.wrapping_add(maj);
            z=g;g=f;f=e;e=d.wrapping_add(t1);d=c;c=b;b=a;a=t1.wrapping_add(t2);
        }
        for (word,delta) in h.iter_mut().zip([a,b,c,d,e,f,g,z]){*word=word.wrapping_add(delta);}
    }
    h.iter().map(|x|format!("{x:08x}")).collect()
}
fn u16at(d:&[u8],at:usize)->Result<u16>{
    let a=d.get(at..at.checked_add(2).ok_or("offset overflow")?).ok_or("truncated u16")?;
    Ok(u16::from_le_bytes([a[0],a[1]]))
}
fn u32at(d:&[u8],at:usize)->Result<u32>{
    let a=d.get(at..at.checked_add(4).ok_or("offset overflow")?).ok_or("truncated u32")?;
    Ok(u32::from_le_bytes([a[0],a[1],a[2],a[3]]))
}
#[derive(Debug)]
struct Section{name:String,rva:u32,virtual_size:u32,raw_at:usize,raw_size:usize,flags:u32}
#[derive(Debug)]
struct Pe{base:u32,entry:u32,sections:Vec<Section>}
impl Pe{
    fn section(&self,name:&str)->Result<&Section>{
        self.sections.iter().find(|s|s.name==name).ok_or_else(||format!("missing {name} section"))
    }
    fn range<'a>(&self,d:&'a [u8],rva:u32,len:usize)->Result<&'a [u8]>{
        if len==0{return Err("zero-byte RVA read".into());}
        for s in &self.sections{
            let Some(relative)=rva.checked_sub(s.rva) else{continue;};
            let rel=relative as usize;
            let covered=s.raw_size.min(if s.virtual_size==0{s.raw_size}else{s.virtual_size as usize});
            if rel.checked_add(len).is_some_and(|end|end<=covered){
                let at=s.raw_at.checked_add(rel).ok_or("PE file offset overflow")?;
                return d.get(at..at.checked_add(len).ok_or("PE file span overflow")?)
                    .ok_or_else(||"RVA not within file".into());
            }
        }
        Err(format!("RVA 0x{rva:08X} not fully backed"))
    }
}
fn parse_pe(d:&[u8])->Result<Pe>{
    if d.len()<64||d.get(..2)!=Some(b"MZ"){return Err("not MZ".into());}
    let nt=u32at(d,0x3C)? as usize;
    if d.get(nt..nt.checked_add(4).ok_or("NT overflow")?)!=Some(b"PE\0\0"){
        return Err("invalid PE signature".into());
    }
    if u16at(d,nt+4)?!=0x14C{return Err("not x86 PE".into());}
    let count=u16at(d,nt+6)? as usize;
    if !(1..=24).contains(&count){return Err("invalid section count".into());}
    let optional_len=u16at(d,nt+20)? as usize;
    let opt=nt.checked_add(24).ok_or("optional offset overflow")?;
    if optional_len<0x60 || d.get(opt..opt.checked_add(optional_len).ok_or("optional length overflow")?).is_none(){
        return Err("truncated optional header".into());
    }
    if u16at(d,opt)?!=0x10B{return Err("not PE32".into());}
    let base=u32at(d,opt+28)?;
    let entry=u32at(d,opt+16)?;
    let table=opt+optional_len;
    let mut sections=Vec::new();
    for index in 0..count{
        let at=table.checked_add(index.checked_mul(40).ok_or("section overflow")?).ok_or("section overflow")?;
        let row=d.get(at..at.checked_add(40).ok_or("section header overflow")?).ok_or("truncated section")?;
        let name=String::from_utf8_lossy(row[..8].split(|x|*x==0).next().unwrap_or(&[])).to_string();
        let virtual_size=u32at(d,at+8)?;
        let rva=u32at(d,at+12)?;
        let raw_size=u32at(d,at+16)? as usize;
        let raw_at=u32at(d,at+20)? as usize;
        let flags=u32at(d,at+36)?;
        if d.get(raw_at..raw_at.checked_add(raw_size).ok_or("raw section overflow")?).is_none(){
            return Err(format!("section {name} outside file"));
        }
        sections.push(Section{name,rva,virtual_size,raw_at,raw_size,flags});
    }
    Ok(Pe{base,entry,sections})
}
fn exact_file(p:&Path,size:usize,sha:&str)->Result<Vec<u8>>{
    let m=fs::metadata(p).map_err(|e|format!("{}: {e}",p.display()))?;
    if !m.is_file()||m.len()!=size as u64{
        return Err(format!("{}: unsupported length (expected {size})",p.display()));
    }
    let d=fs::read(p).map_err(|e|format!("{}: {e}",p.display()))?;
    if d.len()!=size{return Err("file changed during read".into());}
    let actual=sha256(&d);
    if actual!=sha{return Err(format!("{}: unknown SHA-256 {actual}",p.display()));}
    Ok(d)
}
#[derive(Debug,PartialEq,Eq)]
struct Delta{different:usize,runs:usize,clusters:Vec<(usize,usize,usize)>}
fn delta(a:&[u8],b:&[u8],max_gap:usize)->Result<Delta>{
    if a.len()!=b.len(){return Err("unequal code sizes".into());}
    let mut intervals=Vec::new();
    let mut i=0;
    while i<a.len(){
        if a[i]==b[i]{i+=1;continue;}
        let start=i;
        while i<a.len()&&a[i]!=b[i]{i+=1;}
        intervals.push((start,i));
    }
    let different=intervals.iter().map(|(s,e)|e-s).sum();
    let mut clusters:Vec<(usize,usize,usize)>=Vec::new();
    for (s,e) in &intervals{
        if let Some(last)=clusters.last_mut(){
            if *s-last.1<=max_gap{last.1=*e;last.2+=e-s;continue;}
        }
        clusters.push((*s,*e,e-s));
    }
    Ok(Delta{different,runs:intervals.len(),clusters})
}
fn next_state(previous:u32)->u32{
    ((u64::from(previous ^ 0x075B_D924)*16807)%2_147_483_647) as u32
}
fn check_icd(d:&[u8])->Result<usize>{
    if d.len()!=ICD_LEN||d.first()!=Some(&0x5B)||(d.len()-1)%4!=0{
        return Err("ICD alignment differs".into());
    }
    let mut state=0x5611_AA5Bu32;
    let mut count=0usize;
    for word in d[1..].chunks_exact(4){
        state=next_state(state);
        if word!=state.to_le_bytes().as_slice(){
            return Err(format!("ICD PRNG mismatch at DWORD {count}"));
        }
        count+=1;
    }
    if count!=170_891||state!=0x2904_1FEC{
        return Err("ICD final boundary differs".into());
    }
    Ok(count)
}
fn help(){
    println!("rayman2-inspect — exact-edition, read-only Rayman 2 research\n\
Usage:\n\
  rayman2-inspect --retail Rayman2-CD.exe [--gog Rayman2-GOG.exe] [--icd RAYMAN2.ICD]\n\
  rayman2-inspect --help\n\
No launch, patch, decrypt, write or redistribution of game files.\n\
GOG is a modified edition, not an authenticated unwrapped retail executable.");
}
fn run()->Result<()>{
    let (mut retail,mut gog,mut icd)=(None::<PathBuf>,None::<PathBuf>,None::<PathBuf>);
    let mut args=env::args().skip(1);
    while let Some(key)=args.next(){
        if key=="--help"||key=="-h"{
            if args.next().is_some(){return Err("unexpected argument after --help".into());}
            help();return Ok(());
        }
        let path=PathBuf::from(args.next().ok_or_else(||format!("missing value for {key}"))?);
        match key.as_str(){
            "--retail" if retail.is_none()=>retail=Some(path),
            "--gog" if gog.is_none()=>gog=Some(path),
            "--icd" if icd.is_none()=>icd=Some(path),
            _=>return Err(format!("unknown/repeated argument {key}")),
        }
    }
    let path=retail.ok_or("missing --retail; see --help")?;
    let original=exact_file(&path,CD_LEN,CD_SHA)?;
    let cp=parse_pe(&original)?;
    if cp.base!=0x400000||cp.entry!=0x5FCC0||cp.sections.len()!=3{
        return Err("CD PE header disagrees with pinned edition".into());
    }
    let cs=cp.section(".text")?;
    if cs.rva!=TEXT_RVA||cs.raw_size!=TEXT_LEN||cs.flags&0x2000_0000==0{
        return Err("unexpected CD .text geometry or flags".into());
    }
    let code=cp.range(&original,TEXT_RVA,TEXT_LEN)?;
    println!("CD Rayman2.exe VERIFIED: {CD_LEN} bytes SHA-256 {CD_SHA}");
    println!("  PE32 entry VA 0x{:08X}; {} sections; original code {} bytes",
             cp.base+cp.entry,cp.sections.len(),TEXT_LEN);
    println!("  Original x86 game code is present on disk; no whole-section decrypt inferred.");
    if let Some(path)=gog{
        let modified=exact_file(&path,GOG_LEN,GOG_SHA)?;
        let gp=parse_pe(&modified)?;
        if gp.base!=cp.base||gp.entry!=cp.entry||gp.sections.len()!=6{
            return Err("GOG PE differs from pinned edition".into());
        }
        gp.section(".extra")?;
        let active=gp.range(&modified,TEXT_RVA,TEXT_LEN)?;
        let archive=gp.range(&modified,COPY_RVA,TEXT_LEN)?;
        if archive!=code{return Err("GOG .extra copy != original CD code".into());}
        let stats=delta(code,active,512)?;
        if stats.different!=13_269||stats.runs!=102||stats.clusters.len()!=10{
            return Err(format!("GOG active code delta differs: {stats:?}"));
        }
        println!("GOG Rayman2.exe VERIFIED: {GOG_LEN} bytes SHA-256 {GOG_SHA}");
        println!("  archived CD code at RVA 0x{COPY_RVA:08X}: {} bytes exact match",TEXT_LEN);
        println!("  active code differs by {} bytes in {} runs / {} clusters (gap <=512)",
                 stats.different,stats.runs,stats.clusters.len());
        for (i,(s,e,n)) in stats.clusters.iter().enumerate(){
            println!("    {:2}: VA 0x{:08X}..0x{:08X} (exclusive): {n} changed bytes",
                     i+1,cp.base+TEXT_RVA+*s as u32,cp.base+TEXT_RVA+*e as u32);
        }
        println!("  Changed GOG instructions are not automatically SafeDisc-specific.");
    }
    if let Some(path)=icd{
        let aux=exact_file(&path,ICD_LEN,ICD_SHA)?;
        let n=check_icd(&aux)?;
        println!("RAYMAN2.ICD VERIFIED: {ICD_LEN} bytes SHA-256 {ICD_SHA}");
        println!("  masked Park-Miller stream: {n} verified DWORDs + 1 prefix byte");
        println!("  Stream identity does not establish an encrypted PE or physical disc authenticity.");
    }
    println!("RESULT: read-only audit; no unpacking or game execution.");
    Ok(())
}
fn main(){
    if let Err(error)=run(){eprintln!("rayman2-inspect ERROR: {error}");process::exit(1);}
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn sha_vectors(){
        assert_eq!(sha256(b""),"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256(b"abc"),"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
    #[test]
    fn code_delta_boundaries(){
        let a=[0u8;20];let mut b=a;
        b[2]=1;b[3]=1;b[7]=1;b[17]=1;
        let s=delta(&a,&b,3).unwrap();
        assert_eq!((s.different,s.runs),(4,3));
        assert_eq!(s.clusters,vec![(2,8,3),(17,18,1)]);
        assert!(delta(&a,&a[..19],3).is_err());
    }
    #[test]
    fn prng_matches_original_last_word(){
        let mut state=0x5611_AA5B;
        for _ in 0..170_891{state=next_state(state);}
        assert_eq!(state,0x2904_1FEC);
    }
    #[test]
    fn pe_parser_rejects_malformed_inputs(){
        assert!(parse_pe(b"MZhello").is_err());
        let mut d=vec![0u8;0x300];
        d[..2].copy_from_slice(b"MZ");
        d[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        d[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        d[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        d[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
        d[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
        d[0xb4..0xb8].copy_from_slice(&0x400000u32.to_le_bytes());
        let at=0x178;
        d[at..at+8].copy_from_slice(b".text\0\0\0");
        d[at+8..at+12].copy_from_slice(&0x20u32.to_le_bytes());
        d[at+12..at+16].copy_from_slice(&0x1000u32.to_le_bytes());
        d[at+16..at+20].copy_from_slice(&0x20u32.to_le_bytes());
        d[at+20..at+24].copy_from_slice(&0x200u32.to_le_bytes());
        let pe=parse_pe(&d).unwrap();
        assert_eq!(pe.range(&d,0x1000,0x20).unwrap(),&d[0x200..0x220]);
        assert!(pe.range(&d,0x101f,2).is_err());
        assert!(pe.section(".extra").is_err());
        d[at+20..at+24].copy_from_slice(&0xfffffff0u32.to_le_bytes());
        assert!(parse_pe(&d).is_err());
    }
}
