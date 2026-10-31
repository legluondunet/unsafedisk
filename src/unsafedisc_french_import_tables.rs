// Rebuild the exact French Crimson Skies 1.0.2.0 .idata section, in memory.
// Requires SHA-gated owner-owned ICD (caller responsibility).
// The 134 nonzero import pointers are decoded by a key DISCOVERED from the
// encrypted ICD; the two order permutations below are VERSION-SPECIFIC
// metadata established once using the historical Windows 98 reference.
// This is not a generic SafeDisc IAT permutation recovery algorithm.
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};

pub const EXPECTED_IDATA_SHA: &str =
    "c8674927a6a2f6c53330b9692dca084084cb5cfef9acc3ecaab1bb8a0cbd7534";

const KERNEL_ORDER: [i16;74] = [
    53,72,68,34,69,39,43,28,63,27,54,66,56,11,51,4,71,45,64,30,
    36,37,55,10,48,29,44,32,31,15,67,12,17,62,18,60,-1,2,26,58,
    52,24,65,3,35,22,46,70,16,9,20,40,13,49,25,57,1,47,8,73,
    42,19,38,50,41,7,59,21,6,14,33,5,61,23
];
const USER_ORDER: [i16;62] = [
    38,30,61,23,5,51,43,52,-1,27,34,12,21,4,7,9,46,36,6,55,
    31,54,17,8,15,29,49,48,45,10,37,2,14,53,24,1,3,13,57,39,
    16,47,20,40,56,42,33,28,58,44,18,59,11,22,60,41,26,50,32,19,35,25
];
const NAME_RANGES: [(u32,u32);3] = [
    (0x0062_0E24,0x0062_12E2),
    (0x0062_12F0,0x0062_16CE),
    (0x0062_24C2,0x0062_2526),
];
const TIMESTAMP_VALUE: u32 = 0xAD2B_0000;

#[derive(Debug)]
pub struct ImportRebuild {
    pub idata: Vec<u8>,
    pub inferred_pointer_xor: u32,
    pub matched_protected_thunks: usize,
    pub reconstructed_thunks: usize,
}

fn word(blob:&[u8],offset:usize)->Result<u32,String>{
    let end=offset.checked_add(4).ok_or("import word offset overflow")?;
    let data=blob.get(offset..end).ok_or("import word outside .idata")?;
    Ok(u32::from_le_bytes(data.try_into().map_err(|_|"invalid import DWORD")?))
}
fn put_word(blob:&mut [u8],offset:usize,value:u32)->Result<(),String>{
    let end=offset.checked_add(4).ok_or("import write offset overflow")?;
    let target=blob.get_mut(offset..end).ok_or("import write outside .idata")?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn offset(rva:u32,base:u32,len:usize)->Result<usize,String>{
    let p=rva.checked_sub(base).ok_or("RVA before .idata")? as usize;
    if p>=len {return Err("RVA outside .idata".into());}
    Ok(p)
}
fn collect_name_rvas(encrypted:&[u8],base:u32)
    ->Result<(Vec<u32>,Vec<u32>),String>
{
    let mut all=Vec::new();
    let mut kernel=Vec::new();
    let mut user=Vec::new();
    for (region,(start,end)) in NAME_RANGES.iter().enumerate() {
        let mut p=offset(*start,base,encrypted.len())?;
        let stop=offset(*end-1,base,encrypted.len())?+1;
        while p<stop {
            let n=encrypted[p] as usize;
            if !(2..=128).contains(&n){return Err("invalid encoded API name length".into());}
            let next=p.checked_add(2+n+(n&1)).ok_or("API name extent overflow")?;
            if next>stop {return Err("encoded API name crosses region boundary".into());}
            let rva=base.checked_add(p as u32).ok_or("name RVA overflow")?;
            all.push(rva);
            if region==1 {user.push(rva);} else {kernel.push(rva);}
            p=next;
        }
        if p!=stop {return Err("encoded name region misalignment".into());}
    }
    if all.len()!=136 || kernel.len()!=74 || user.len()!=62 {
        return Err(format!("unexpected import-name counts: {}/{}/{}",
            all.len(),kernel.len(),user.len()));
    }
    Ok((kernel,user))
}

struct Table {
    ilt:usize,
    iat:usize,
    source:Vec<u32>,
    kernel:bool,
}

pub fn reconstruct(original:&[u8],decoded_names:&[u8],base:u32)
    ->Result<ImportRebuild,String>
{
    if original.len()!=0x4000 || decoded_names.len()!=original.len() {
        return Err("expected exactly 0x4000-byte .idata section".into());
    }
    let (kernel_names,user_names)=collect_name_rvas(original,base)?;
    let mut tables=Vec::new();
    for descriptor in 0..21usize {
        let pos=descriptor*20;
        if word(original,pos+4)?!=0 {
            return Err("unexpected protected descriptor timestamp".into());
        }
        let name=offset(word(original,pos+12)?,base,original.len())?;
        let tail=original.get(name..).ok_or("DLL name outside .idata")?;
        let end=tail.iter().position(|x|*x==0).ok_or("unterminated DLL import name")?;
        let dll=String::from_utf8_lossy(&tail[..end]).to_ascii_lowercase();
        let (count,kernel) = match dll.as_str() {
            "kernel32.dll" => (74,true),
            "user32.dll" => (62,false),
            _ => continue,
        };
        let ilt=offset(word(original,pos)?,base,original.len())?;
        let iat=offset(word(original,pos+16)?,base,original.len())?;
        let mut source=Vec::with_capacity(count);
        for i in 0..count {
            let p=4*i;
            let a=word(original,ilt+p)?;
            let b=word(original,iat+p)?;
            if a!=b {return Err("protected ILT/IAT mismatch".into());}
            if (i==0)!= (a==0) {return Err("unexpected protected import-thunk zero".into());}
            source.push(a);
        }
        tables.push(Table{ilt,iat,source,kernel});
    }
    if tables.len()!=2 || tables.iter().filter(|t|t.kernel).count()!=1 {
        return Err("expected exactly one KERNEL32 and one USER32 import descriptor".into());
    }

    // Blindly derive the pointer XOR from encrypted words and *encoded*
    // API-record start addresses, not from a plaintext EXE or a known key.
    let all_names:Vec<u32>=kernel_names.iter().chain(user_names.iter()).copied().collect();
    let mut votes=HashMap::<u32,usize>::new();
    let mut nonzero_count=0usize;
    for t in &tables {
        for &cipher in t.source.iter().skip(1) {
            nonzero_count+=1;
            for &name in &all_names {
                *votes.entry(cipher^name).or_default()+=1;
            }
        }
    }
    let (key,votes_for_key)=votes.into_iter()
        .max_by_key(|&(key,votes)| (votes,std::cmp::Reverse(key)))
        .ok_or("no import XOR candidates")?;
    if nonzero_count!=134 || votes_for_key!=134 {
        return Err(format!("ambiguous import XOR: matched {votes_for_key}/{nonzero_count}"));
    }

    let mut out=decoded_names.to_vec();
    let mut decoded_count=0usize;
    for t in &tables {
        let (name_rvas,order) = if t.kernel {
            (&kernel_names[..],&KERNEL_ORDER[..])
        } else {
            (&user_names[..],&USER_ORDER[..])
        };
        let possible:HashSet<u32>=name_rvas.iter().copied().collect();
        let decrypted=t.source.iter().skip(1).map(|v|v^key).collect::<Vec<_>>();
        let actual:HashSet<u32>=decrypted.iter().copied().collect();
        if actual.len()!=decrypted.len() || !actual.is_subset(&possible) {
            return Err("import XOR result contains duplicate/out-of-group RVA".into());
        }
        let missing:Vec<u32>=possible.difference(&actual).copied().collect();
        if missing.len()!=1 {return Err("not exactly one missing import RVA".into());}
        let mut used=HashSet::new();
        for (dst_index,&src_index) in order.iter().enumerate() {
            let name=if src_index==-1 {missing[0]} else {
                let source_index=src_index as usize;
                if source_index>=t.source.len() || source_index==0 {
                    return Err("invalid version-specific permutation index".into());
                }
                t.source[source_index]^key
            };
            if !used.insert(name) {return Err("version-specific import permutation duplicates RVA".into());}
            put_word(&mut out,t.ilt+4*dst_index,name)?;
            put_word(&mut out,t.iat+4*dst_index,name)?;
            decoded_count+=1;
        }
        if used!=possible {return Err("permutation does not cover all API names".into());}
    }
    // These historical values are part of unSafeDisc's output format,
    // not evidence that the original protected PE needed them to run.
    for i in 0..21 {put_word(&mut out,i*20+4,TIMESTAMP_VALUE)?;}
    // Historical cosmetic DLL-capitalization convention.
    for i in 0..21 {
        let name=offset(word(original,i*20+12)?,base,original.len())?;
        if original.get(name..name+12)==Some(&b"KERNEL32.dll"[..]) {
            out[name..name+12].copy_from_slice(b"KeRNeL32.dll");
        }
    }
    Ok(ImportRebuild{
        idata:out,inferred_pointer_xor:key,
        matched_protected_thunks:votes_for_key,
        reconstructed_thunks:decoded_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permutations_cover_each_source_index_once(){
        for order in [&KERNEL_ORDER[..],&USER_ORDER[..]] {
            let n=order.len();
            let mut checked=vec![false;n];
            let mut missing=0;
            for &i in order {
                if i<0 {assert_eq!(i,-1);missing+=1;continue;}
                let i=i as usize;
                assert!(i>0 && i<n && !checked[i]);
                checked[i]=true;
            }
            assert_eq!(missing,1);
            assert!(checked.iter().skip(1).all(|x|*x));
        }
    }
}
