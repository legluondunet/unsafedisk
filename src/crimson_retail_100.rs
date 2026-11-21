// Crimson Skies retail CD v1.0.0.1 reconstruction experiment.
// GPL-3.0-or-later. No game bytes, protected DLL or memory snapshot included.
// Uses only strictly SHA-pinned original CD loader+ICD sources.
// WARNING: the 1.00 candidate is NOT the official 1.02 and has NOT passed gameplay tests.
// Canonical import positions are recovered from cross-version context, including
// indirect MOV/JMP sites. Gameplay validation and complete semantic proof remain open.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

type Result<T> = std::result::Result<T,String>;
const SIZE:usize=2_560_095;
const RESULT_LEN:usize=2_560_000;
const RESULT_SHA:&str="11242994ee568065a30fcfcfa1c9c23f86d60ea56f937bb00648bf9558fa1e70";
const IDATA_SHA:&str="a35c901dbec1e96c0b0809d1ba13a6656b12d0f003e5f4fead72139f208e5ba9";

#[derive(Clone,Copy)]
struct Profile {
    edition:&'static str,
    loader_size:usize,loader_sha:&'static str,icd_sha:&'static str,
    name_seed:u8,import_xor:u32,code_checksum:u32,tea:[u32;4],
}
const US:Profile=Profile{
    edition:"US/EU 1.0.0.1",loader_size:344851,
    loader_sha:"7d6029471d4e5f2c7f4b08ce86c0ffd1f9bc8c697cf3952695fd68ff011f25a1",
    icd_sha:"c586773b0475aa6560b4464e5aa0d1da4cc249099b8db16be7240f4221d7e59d",
    name_seed:0xDF,import_xor:0x74961255,code_checksum:0x8F2A9090,
    tea:[0x74961255,0xE9C75015,0xCF10A905,0x82F59CF5]
};
const DE:Profile=Profile{
    edition:"German 1.0.0.1",loader_size:344993,
    loader_sha:"a4ba27ae4070952611872f3120ab5859469691ad0954203a83dbfe2f2e0750af",
    icd_sha:"5fb33f3bdc6977283620fe2bfe4f1cc734cf64ef6cec844e8f983e25986b7172",
    name_seed:0x94,import_xor:0x3FA909A4,code_checksum:0xA7D3349A,
    tea:[0x3FA909A4,0xA2765BE4,0x852D72B4,0xC9488EC4]
};

// Canonical import index -> API-name record number in the ORIGINAL CD.
// Derived using cross-version instruction-context matches with the owner's
// independently prepared 1.02 reference; no proprietary API implementation.
// Indices are inferred from direct calls and additional indirect IAT uses.
// A few positions within modified blocks use unique near-code anchor alignment;
// validate gameplay before claiming complete semantic equivalence.
const K_ORDER:[usize;74]=[
 1,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,20,21,19,
 23,24,22,26,27,25,29,30,28,32,33,31,35,36,34,38,39,37,41,42,
 40,44,45,43,47,48,46,49,50,51,52,53,54,55,56,57,58,60,61,59,
 63,64,62,68,69,67,0,73,72,71,66,65,70,2
];
const U_ORDER:[usize;60]=[
 52,51,50,49,53,54,48,46,45,44,43,57,58,47,56,55,37,36,35,34,
 33,32,31,30,29,28,27,0,9,8,59,40,39,38,42,41,1,2,13,12,
 15,26,25,24,23,22,21,20,19,18,17,16,7,14,4,10,11,3,5,6
];

// Explicit 232 protected indirect-call RVAs, found by comparing the two
// hash-verified owners' protected ICD images. Numbers are positions, not code.
const SHIFT_RVAS:&str=r#"
0012d4 002e3a 002edc 002ef4 002f5e 002fdc 00339f 0033ee 0043fa 004585 0047e7 004b2a
004bfe 004cb0 004cfe 004d52 004e72 00508d 005160 0051ec 005207 006231 0065f6 00660f
006618 006627 0066a6 0068a1 00692b 006958 006d38 006d43 007069 007076 007130 00774f
0079b2 007a75 007b52 007fc9 0083af 00935b 0093ad 0093d8 0094de 0095a8 009a49 00ab29
00aee9 00b076 00b766 00b80d 00b909 00bac9 00be2d 00bf10 00de43 00df7d 00e3de 00e630
00e9e0 00ea0f 00f085 00f091 010ca4 010cb5 010e0c 011450 01159b 0115b3 0116d8 0117d1
011929 01195c 0149b9 014a4e 014a59 0191f8 019349 019358 0193ce 032685 038fcf 039f68
03b90e 0415b7 0415da 0418d4 041a0d 041a2c 041b68 041d32 041dec 041fa0 042060 04333c
049136 064cc5 06a826 06a898 09fb86 0a6066 0a609f 0a60b3 0a60ba 0a60f8 0a6179 0a629f
0a63ca 0a686b 0a6882 0a68ab 0a68f4 0a69c5 0a69d2 0a69da 0a6e71 0a7622 0ad6a6 0ad6c5
0ad762 0ca753 0ca777 0ca790 0ca813 131cc5 13203d 133d0b 136175 15f311 15f336 15f34f
15f3da 176d3c 198991 198a7d 199223 19936f 19952f 199558 19a0dd 19a111 19a4f0 19a5c1
19a640 19b125 1a452b 1a455d 1a456a 1a4aae 1a4b2a 1a4b3b 1a58c1 1a58e6 1a593f 1a5e2c
1a5e3d 1a5e54 1a5ecb 1a5ee1 1a5eec 1a5f61 1a5fb0 1a5fec 1a605e 1a7605 1a7621 1a7639
1a76a7 1a76b8 1ae50a 1b0825 1b088f 1b0dcb 1b1b65 1b1b80 1b1c11 1b1c2f 1b2627 1b293c
1b2a1a 1bafa0 1bafe8 1bb002 1bb0f9 1bb116 1bb171 1bb189 1bb19e 1bb1c9 1bb1e7 1bb4cf
1bb9b3 1bb9e0 1bbc7b 1bbd10 1bbd30 1bbd37 1c2abb 1c2b64 1c2be6 1c2c48 1c3095 1c32b3
1c32d0 1c345a 1c3468 1c3b06 1c77b5 1c77cd 1c7eca 1c81b0 1c834b 1ca370 1ca767 1cc032
1cc050 1cc188 1cc198 1cf035 1cf04b 1cf085 1cf09b 1cf1bf 1cf200 1d84ed 1f3046 1f4d7a
1f4ebc 1f552e 1f55c4 1f5932
"#;

fn shift_set()->Result<HashSet<u32>>{
    let mut set=HashSet::new();
    for value in SHIFT_RVAS.split_whitespace(){
        let rva=u32::from_str_radix(value,16).map_err(|_|"invalid shift metadata RVA")?;
        if !set.insert(rva){return Err("duplicate shift RVA".into());}
    }
    if set.len()!=232{return Err(format!("expected 232 shifted call RVAs, got {}",set.len()));}
    Ok(set)
}

fn w16(data:&[u8],at:usize)->Result<u16>{
    let b=data.get(at..at.checked_add(2).ok_or("u16 overflow")?).ok_or("u16 out of bounds")?;
    Ok(u16::from_le_bytes([b[0],b[1]]))
}
fn w32(data:&[u8],at:usize)->Result<u32>{super::read_u32(data,at)}
fn set32(data:&mut [u8],at:usize,word:u32)->Result<()>{
    let end=at.checked_add(4).ok_or("write overflow")?;
    data.get_mut(at..end).ok_or("write outside buffer")?
        .copy_from_slice(&word.to_le_bytes());
    Ok(())
}
fn range(data:&[u8],start:usize,count:usize)->Result<&[u8]>{
    let end=start.checked_add(count).ok_or("slice range overflow")?;
    data.get(start..end).ok_or("range outside verified image".into())
}
fn ident<T:Eq+std::fmt::Debug>(found:T,expected:T,label:&str)->Result<()>{
    if found!=expected{Err(format!("{label}: got {found:?}, expected {expected:?}"))}else{Ok(())}
}
fn canonical_array_is_permutation(values:&[usize])->bool{
    let mut sorted=values.to_vec();sorted.sort_unstable();
    sorted.iter().enumerate().all(|(index,&value)|index==value)
}

struct ImportState {
    decoded:Vec<u8>,k_iat:u32,u_iat:u32,
}
// Names are decoded from the protected CD, not loaded from the 1.02 EXE.
// The record start lists are edition-independent; encoded bytes are not.
fn imports(icd:&[u8],pe:&super::Pe32,p:&Profile)->Result<ImportState>{
    const BASE:u32=0x619000;
    let sec=pe.section(b".idata")?;
    ident((sec.virtual_address,sec.raw_len),(BASE,0x4000usize),"1.00 import geometry")?;
    let protected=range(icd,sec.raw_offset,sec.raw_len)?;
    let mut out=protected.to_vec();
    let mut kernel=Vec::new();
    let mut user=Vec::new();
    for (begin,end,is_kernel) in [(0x1e14usize,0x22d2usize,true),
                                   (0x22e0,0x2696,false),
                                   (0x348a,0x34ee,true)] {
        let mut at=begin;
        while at<end {
            let len=*protected.get(at).ok_or("name length beyond section")? as usize;
            if !(4..=128).contains(&len){return Err("unknown encrypted API name length".into());}
            let stop=at.checked_add(len+2).ok_or("name record length overflow")?;
            if stop>end{return Err("API record escapes verified run".into());}
            if protected[at+1]!=(protected[at+2]^p.name_seed^0x3d){
                return Err("unknown encrypted API header".into());
            }
            let mut previous=p.name_seed;
            for j in 0..len{
                let cipher=protected[at+2+j];
                let plaintext=cipher^previous;
                if j+1==len{
                    if plaintext!=0{return Err("decoded API name lacks NUL".into());}
                }else if !(0x20..=0x7e).contains(&plaintext){
                    return Err("decoded API name not printable ASCII".into());
                }
                out[at+2+j]=plaintext;
                previous=cipher;
            }
            out[at]=0;
            out[at+1]=0;
            let name_rva=BASE+at as u32;
            if is_kernel{kernel.push(name_rva);}else{user.push(name_rva);}
            at=stop+(len&1);
        }
        if at!=end{return Err("encoded API run has broken alignment".into());}
    }
    ident((kernel.len(),user.len()),(74,60),"API counts")?;
    if !canonical_array_is_permutation(&K_ORDER)
       || !canonical_array_is_permutation(&U_ORDER){
        return Err("untrusted import order metadata".into());
    }
    let mut k_iat=None;
    let mut u_iat=None;
    let mut recognised=0usize;
    let mut original_pointers=0usize;
    for descriptor in 0..21usize {
        let at=descriptor*20;
        ident(w32(protected,at+4)?,0u32,"protected import timestamp")?;
        let name_rva=w32(protected,at+12)?;
        let name_pos=name_rva.checked_sub(BASE).ok_or("DLL name RVA before .idata")? as usize;
        let tail=protected.get(name_pos..).ok_or("DLL name outside .idata")?;
        let terminator=tail.iter().position(|&b|b==0).ok_or("unterminated DLL name")?;
        let dll=std::str::from_utf8(&tail[..terminator])
            .map_err(|_|"non-ASCII DLL name")?;
        let target=if dll.eq_ignore_ascii_case("kernel32.dll"){
            Some((&kernel[..],&K_ORDER[..],&mut k_iat))
        }else if dll.eq_ignore_ascii_case("user32.dll"){
            Some((&user[..],&U_ORDER[..],&mut u_iat))
        }else{None};
        // Historical time stamp is unSafeDisc 1.5.5 output convention.
        set32(&mut out,at+4,0xad2b0000)?;
        if let Some((names,order,target_iat))=target {
            recognised+=1;
            let ilt=w32(protected,at)?.checked_sub(BASE).ok_or("ILT before section")? as usize;
            let iat_rva=w32(protected,at+16)?;
            let iat=iat_rva.checked_sub(BASE).ok_or("IAT before section")? as usize;
            if target_iat.replace(iat_rva).is_some(){
                return Err("duplicate KERNEL32/USER32 import descriptor".into());
            }
            let mut seen=HashSet::new();
            for (index,&record) in order.iter().enumerate(){
                let before=w32(protected,ilt+index*4)?;
                ident(before,w32(protected,iat+index*4)?,"ILT/IAT encrypted values")?;
                if index==0{
                    ident(before,0u32,"missing initial protected import")?;
                }else {
                    if !names.contains(&(before^p.import_xor)){
                        return Err("encrypted thunk does not decode to own API pool".into());
                    }
                    if !seen.insert(before^p.import_xor){
                        return Err("duplicate decrypted thunk".into());
                    }
                    original_pointers+=1;
                }
                let restored=names[record];
                set32(&mut out,ilt+index*4,restored)?;
                set32(&mut out,iat+index*4,restored)?;
            }
            ident(w32(protected,ilt+names.len()*4)?,0u32,"protected ILT terminator")?;
            ident(w32(protected,iat+names.len()*4)?,0u32,"protected IAT terminator")?;
            ident(seen.len(),names.len()-1,"number of protected API pointers")?;
        }
    }
    ident((recognised,original_pointers),(2usize,132usize),"protected import tables")?;
    if super::sha256(&out)!=IDATA_SHA{
        return Err("reconstructed 1.00 .idata SHA-256 differs from private cross-CD audit".into());
    }
    Ok(ImportState{
        decoded:out,k_iat:k_iat.ok_or("no kernel IAT")?,
        u_iat:u_iat.ok_or("no user IAT")?,
    })
}

fn rebuild(loader:&[u8],icd:&[u8],p:&Profile)->Result<Vec<u8>>{
    ident(icd.len(),SIZE,"retail ICD bytes")?;
    let pe=super::parse_pe32(icd)?;
    let text=pe.section(b".text")?;
    let data=pe.section(b".data")?;
    let idata=pe.section(b".idata")?;
    ident(pe.entry_rva,0x1f2f1cu32,"1.00 entry RVA")?;
    ident((text.virtual_address,text.virtual_size,text.raw_len,text.raw_offset),
          (0x1000u32,2084301u32,2084864usize,0x1000usize),"1.00 text geometry")?;
    ident((idata.virtual_address,idata.raw_len),(0x619000u32,16384usize),"1.00 import section")?;
    ident((data.virtual_address,data.raw_len),(0x214000u32,172032usize),"1.00 data section")?;
    let nt=w32(icd,0x3c)? as usize;
    ident(w32(icd,nt+24+28)?,0x400000u32,"image base")?;
    let (blocks,_)=super::pe_relocation_blocks(icd,&pe)?;
    let mut text_slots=Vec::new();
    let mut data_slots=Vec::new();
    for block in &blocks{
        for &off in &block.highlow_offsets{
            let rva=block.page_rva+u32::from(off);
            if rva>=text.virtual_address && rva<text.virtual_address+text.virtual_size {
                text_slots.push((rva-text.virtual_address) as usize);
            }else if rva>=data.virtual_address && rva<data.virtual_address+data.raw_len as u32{
                data_slots.push((rva-data.virtual_address) as usize);
            }
        }
    }
    text_slots.sort_unstable();data_slots.sort_unstable();
    ident((text_slots.len(),data_slots.len()),(61144usize,990usize),"HIGHLOW counts")?;
    let text_blob=range(icd,text.raw_offset,text.raw_len)?;
    let text_blocks=blocks.iter().filter(|block|
        block.page_rva>=text.virtual_address &&
        block.page_rva<text.virtual_address+text.raw_len as u32)
        .cloned().collect::<Vec<_>>();
    let checksum=super::checksum_pages_bounded_without_highlow(
        text_blob,text.virtual_address,&text_blocks,text.virtual_size as usize,0)?;
    let corroboration=super::checksum_independent_relocation_walk(
        text_blob,text.virtual_address,&text_blocks,text.virtual_size as usize)?;
    ident(checksum,p.code_checksum,"retail code checksum")?;
    ident(corroboration.checksum,checksum,"independent checksum walker")?;
    let (_,raw)=super::locate_raw_key(loader,super::DLL_LEN)?;
    let key=super::construct_tea_candidate(p.import_xor,checksum,pe.entry_rva,raw);
    ident(key,p.tea,"TEA key from owned CD")?;
    let pair=super::unsafedisc_modifier_snapshot::Pair::crimson_static();
    let text_extent=text.virtual_size as usize;
    let text_decoded=super::unsafedisc_candidate_forward::reconstruct_section(
        range(icd,text.raw_offset,text_extent)?,&text_slots,key,&pair)?;
    let data_extent=data.raw_len.min(data.virtual_size as usize);
    let data_decoded=super::unsafedisc_candidate_forward::reconstruct_section(
        range(icd,data.raw_offset,data_extent)?,&data_slots,key,&pair)?;
    ident((text_decoded.fragments,text_decoded.complete_words,
           data_decoded.fragments,data_decoded.complete_words),
          (47709usize,436731usize,322usize,42018usize),"1.00 fragments")?;
    let recovered_imports=imports(icd,&pe,p)?;
    let mut image=range(icd,0,RESULT_LEN)?.to_vec();
    image[text.raw_offset..text.raw_offset+text_extent].copy_from_slice(&text_decoded.bytes);
    image[data.raw_offset..data.raw_offset+data_extent].copy_from_slice(&data_decoded.bytes);
    image[idata.raw_offset..idata.raw_offset+idata.raw_len]
        .copy_from_slice(&recovered_imports.decoded);
    let mut shifted=shift_set()?;
    let mut calls=0usize;
    for &offset in &text_slots {
        if offset<2 {continue;}
        let at=text.raw_offset+offset;
        if range(&image,at-2,2)?!=b"\xff\x15"{continue;}
        let old=w32(&image,at)?;
        let mut chosen=None;
        for (iat,count) in [(recovered_imports.k_iat,74u32),(recovered_imports.u_iat,60u32)]{
            let start=iat.checked_add(0x400000).ok_or("IAT VA overflow")?;
            let end=start+count*4;
            if old>=start && old<end && (old-start)%4==0 {
                chosen=Some((start,count));break;
            }
        }
        let Some((iat,count))=chosen else{continue;};
        calls+=1;
        let rva=text.virtual_address+offset as u32;
        let rotated=shifted.remove(&rva);
        let mut index=(old-iat)/4;
        if rotated {
            let shift=(rva.wrapping_sub(text.virtual_address)
                .wrapping_sub(2).wrapping_add(p.import_xor))%count;
            index=(index+count-shift)%count;
        }
        set32(&mut image,at,iat+index*4)?;
    }
    ident(calls,464usize,"restored indirect API calls")?;
    if !shifted.is_empty(){
        return Err(format!("{} shifted callsites not resolved",shifted.len()));
    }
    let actual=super::sha256(&image);
    if actual!=RESULT_SHA {
        return Err(format!("1.00 output SHA-256 mismatch: {actual}; refusing to write"));
    }
    Ok(image)
}

// New output is created ONLY once SHA-256 of the complete candidate matches
// the independently established, SAME hash from two differently encrypted CDs.
pub fn cli()->Result<()>{
    let mut args=env::args().skip(2);
    let mut loader=None;let mut icd=None;let mut output=None;
    while let Some(flag)=args.next(){
        if flag=="--help"{
            println!("EXPERIMENTAL retail 1.00 reconstruction (not official 1.02)\nUsage: unsafedisc-linux unwrap-retail100 --loader ORIGINAL_CD_CRIMSON.EXE --icd ORIGINAL_CD_CRIMSON.ICD --output NEW-CANDIDATE.EXE\nThe executable is generated locally; no game bytes are bundled. SHA-256 pinned; output must not exist.");
            return Ok(());
        }
        let value=args.next().ok_or_else(||format!("missing argument for {flag}"))?;
        match flag.as_str(){
            "--loader" if loader.is_none()=>loader=Some(PathBuf::from(value)),
            "--icd" if icd.is_none()=>icd=Some(PathBuf::from(value)),
            "--output" if output.is_none()=>output=Some(PathBuf::from(value)),
            _=>return Err(format!("unexpected/repeated argument {flag}")),
        }
    }
    let loader=loader.ok_or("missing --loader")?;
    let icd=icd.ok_or("missing --icd")?;
    let output=output.ok_or("missing --output")?;
    if fs::symlink_metadata(&output).is_ok(){
        return Err("REFUSING: output already exists".into());
    }
    let meta=fs::symlink_metadata(&icd)
        .map_err(|e|format!("cannot access ICD '{}': {e}",icd.display()))?;
    if !meta.file_type().is_file()||meta.len()!=SIZE as u64{
        return Err(format!("ICD '{}' is not a regular verified-size 1.00 source (got {} bytes; expected {SIZE})",icd.display(),meta.len()));
    }
    let cipher=fs::read(&icd)
        .map_err(|e|format!("cannot read ICD '{}': {e}",icd.display()))?;
    let hash=super::sha256(&cipher);
    let p=if hash==US.icd_sha{US}else if hash==DE.icd_sha{DE}else{
        return Err(format!("unsupported 1.00 CD ICD SHA-256 {hash}"));
    };
    let loader=super::read_original(&loader,p.loader_size,p.loader_sha)?;
    println!("Authenticated {} CD pair; computing candidate locally...",p.edition);
    let image=rebuild(&loader,&cipher,&p)?;
    let mut file=fs::OpenOptions::new().write(true).create_new(true)
        .open(&output).map_err(|e|format!("cannot create new candidate: {e}"))?;
    if let Err(e)=file.write_all(&image).and_then(|_|file.sync_all()){
        drop(file);
        let _=fs::remove_file(&output);
        return Err(format!("incomplete output removed: {e}"));
    }
    println!("CREATED experimental v1.00 PE32: {} bytes; SHA-256 {}",image.len(),RESULT_SHA);
    println!("NOTICE: IAT mapping is reconstructed experimentally; Windows/gameplay validation remains pending. This is NOT the 1.02 EXE accepted by CrimsonSkiesFix.");
    Ok(())
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn metadata_is_unique_and_complete(){
        assert_eq!(shift_set().unwrap().len(),232);
        assert!(canonical_array_is_permutation(&K_ORDER));
        assert!(canonical_array_is_permutation(&U_ORDER));
        assert_eq!(RESULT_SHA.len(),64);
    }
    #[test]
    fn reject_no_pe(){
        assert!(super::super::parse_pe32(&[0;128]).is_err());
    }
}
