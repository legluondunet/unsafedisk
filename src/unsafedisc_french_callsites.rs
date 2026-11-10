// Exact-edition read-only restoration of 245 French .text import call-site
// relocation DWORDs. Positions are reference-guided metadata from the user's
// Windows 98 unSafeDisc 1.5.5 output; this is not generic SafeDisc recovery.
// No proprietary game code/data is included or written to disk.
// SPDX-License-Identifier: GPL-3.0-or-later
use std::collections::HashSet;

pub const RETAIL_PARTIAL_TEXT_SHA256: &str = "d717153d870b229d1a94aea11273c91e943ab6646da441a3d4b01cf6ff35c472";
pub const EXPECTED_PARTIAL_TEXT_SHA256: &str =
    "8a4a1dc7865c0469644a038aa1ea539493305cd3232117aff83fdd03b33b6282";

#[derive(Debug)]
pub struct CallsiteRestore {
    pub text: Vec<u8>,
    pub sites_corrected: usize,
    pub references_kernel: usize,
    pub references_user: usize,
}

fn read_dword(buf:&[u8],at:usize)->Result<u32,String>{
    let end=at.checked_add(4).ok_or("callsite DWORD overflow")?;
    let slice=buf.get(at..end).ok_or("callsite DWORD outside .text")?;
    Ok(u32::from_le_bytes(slice.try_into().map_err(|_|"invalid callsite DWORD")?))
}

pub fn reconstruct(
    original: &[u8], text_rva: u32, raw_start: usize, raw_len: usize,
    highlow_sites:&HashSet<u32>, image_base:u32,
    kernel_iat_rva:u32, user_iat_rva:u32, xor_key:u32,
)->Result<CallsiteRestore,String>{
    reconstruct_version(original,text_rva,raw_start,raw_len,highlow_sites,
        image_base,kernel_iat_rva,user_iat_rva,xor_key,false)
}
pub fn reconstruct_version(
    original:&[u8],text_rva:u32,raw_start:usize,raw_len:usize,
    highlow_sites:&HashSet<u32>,image_base:u32,
    kernel_iat_rva:u32,user_iat_rva:u32,xor_key:u32,retail:bool,
)->Result<CallsiteRestore,String>{
    if original.len()!=2_580_578 || raw_len!=2_105_344 ||
        text_rva!=0x1000 || xor_key!=if retail {0x7496_538F}else{0x6A96_6E30} {
        return Err("unexpected edition/geometry or import key".into());
    }
    let end=raw_start.checked_add(raw_len).ok_or("text section end overflow")?;
    let mut output=original.get(raw_start..end)
        .ok_or("text section outside source ICD")?.to_vec();
    let sites=if retail {
        crate::unsafedisc_retail_metadata::callsites()?
    } else {
        let mut sites=Vec::new();
        for item in include_str!("french_import_callsite_rvas.txt").split_whitespace() {
            let site=u32::from_str_radix(item,16)
                .map_err(|_|"invalid French callsite metadata")?;
            if sites.last().is_some_and(|prev|site<=*prev){
                return Err("unordered French callsite metadata".into());
            }
            sites.push(site);
        }
        if sites.len()!=245 || sites.iter().map(|&v|u64::from(v)).sum::<u64>()!=212_277_808 {
            return Err("French callsite metadata mismatch".into());
        }
        sites
    };

    let kernel_va=image_base.checked_add(kernel_iat_rva)
        .ok_or("kernel IAT preferred address overflow")?;
    let user_va=image_base.checked_add(user_iat_rva)
        .ok_or("user IAT preferred address overflow")?;

    let mut corrected=0usize;
    let mut kernel=0usize;
    let mut user=0usize;
    for site in sites {
        if !highlow_sites.contains(&site) {
            return Err(format!("missing HIGHLOW relocation at 0x{site:08X}"));
        }
        let section_offset=site.checked_sub(text_rva)
            .ok_or("callsite before .text RVA")? as usize;
        if section_offset < 2 {
            return Err("callsite too close to section start".into());
        }
        let word=read_dword(&output,section_offset)?;
        let (base,count,is_kernel)=if word>=kernel_va &&
            word<kernel_va+74*4 && (word-kernel_va)%4==0 {
            (kernel_va,74u32,true)
        } else if word>=user_va && word<user_va+62*4 &&
            (word-user_va)%4==0 {
            (user_va,62u32,false)
        } else {
            return Err(format!("unexpected IAT pointer 0x{word:08X} at 0x{site:08X}"));
        };
        let old_index=(word-base)/4;
        let shift=((site-text_rva-2).wrapping_add(xor_key))%count;
        let new_index=(old_index+count-shift)%count;
        let result=base+4*new_index;
        if result==word {
            return Err(format!("version-specific metadata site unexpectedly unchanged: 0x{site:08X}"));
        }
        output[section_offset..section_offset+4].copy_from_slice(&result.to_le_bytes());
        corrected+=1;
        if is_kernel {kernel+=1;} else {user+=1;}
    }
    let (nk,nu)=if retail {(182,63)}else{(183,62)};
    if corrected!=245 || kernel!=nk || user!=nu {
        return Err(format!("unexpected restored site groups: kernel={kernel} user={user}"));
    }
    Ok(CallsiteRestore {
        text: output,
        sites_corrected:corrected,
        references_kernel:kernel,
        references_user:user
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn edition_metadata_is_sorted_and_bounded(){
        let list:Vec<u32>=include_str!("french_import_callsite_rvas.txt")
            .split_whitespace().map(|x|u32::from_str_radix(x,16).unwrap()).collect();
        assert_eq!(list.len(),245);
        assert!(list.windows(2).all(|w|w[0]<w[1]));
        assert_eq!(list.iter().map(|&x|u64::from(x)).sum::<u64>(),212_277_808);
    }
}
