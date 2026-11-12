// Generic, read-only SafeDisc research diagnostics.
// Do not execute user input or infer decryptability from entropy or file size.
// Non-PE ICD/DLL inputs are valid inspection targets (not a parse failure).

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use super::{parse_pe32, sha256, Result, MAX_INPUT_LEN};

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / total;
            -probability * probability.log2()
        })
        .sum()
}

fn hex_prefix(bytes: &[u8], max_len: usize) -> String {
    bytes
        .iter()
        .take(max_len)
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// Pure formatter so synthetic tests need no proprietary file fixtures.
fn render_report(role: &str, display: &str, bytes: &[u8], details: bool) -> String {
    let mut out = String::new();
    writeln!(out, "{role}: {display} ({} bytes)", bytes.len()).unwrap();
    writeln!(out, "  SHA-256: {}", sha256(bytes)).unwrap();
    writeln!(out, "  Shannon entropy: {:.4} bits/byte (descriptive only)", shannon_entropy(bytes)).unwrap();

    match parse_pe32(bytes) {
        Ok(pe) => {
            writeln!(
                out,
                "  PE32 x86 entry RVA: 0x{:08X}; sections: {}",
                pe.entry_rva,
                pe.sections.len()
            ).unwrap();
            if details {
                for section in &pe.sections {
                    let name_bytes = section.name.split(|byte| *byte == 0).next().unwrap_or(&[]);
                    let name = String::from_utf8_lossy(name_bytes);
                    writeln!(
                        out,
                        "  {name}: RVA=0x{:08X} virtual=0x{:X} raw_offset=0x{:X} raw_length=0x{:X} flags=0x{:08X}",
                        section.virtual_address,
                        section.virtual_size,
                        section.raw_offset,
                        section.raw_len,
                        section.characteristics
                    ).unwrap();
                }
            }
        }
        Err(reason) if bytes.starts_with(b"MZ") => {
            // A malformed, unsupported or packed PE is not a confirmed SafeDisc file.
            writeln!(out, "  MZ header present; x86 PE32 metadata unavailable: {reason}").unwrap();
        }
        Err(_) => {
            // SafeDisc ICD and dplayerx.dll files may be opaque on disk.
            writeln!(out, "  Non-PE32/opaque input: no MZ header at offset 0").unwrap();
        }
    }

    if details {
        writeln!(out, "  First {} bytes: {}", bytes.len().min(32), hex_prefix(bytes, 32)).unwrap();
    }
    out
}

pub fn inspect_inputs(inputs: [(&str, &Path); 3], details: bool) -> Result<()> {
    for (role, path) in inputs {
        let meta = fs::symlink_metadata(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_INPUT_LEN {
            return Err(format!(
                "refusing symlink/non-regular or oversized file: {}",
                path.display()
            ));
        }
        let bytes = fs::read(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if bytes.len() as u64 > MAX_INPUT_LEN {
            return Err(format!("file exceeded maximum input size: {}", path.display()));
        }
        print!("{}", render_report(role, &path.display().to_string(), &bytes, details));
    }
    println!(
        "Read-only generic inspection; high entropy does not prove encryption, and no SafeDisc version, key or decryptability is asserted."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_limits_and_empty_data() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0xAA; 256]), 0.0);
        let balanced: Vec<u8> = (0..=255).map(|n| n as u8).collect();
        assert!((shannon_entropy(&balanced) - 8.0).abs() < 1e-12);
    }

    #[test]
    fn opaque_icd_is_inspectable_without_pe_header() {
        let report = render_report("icd", "synthetic.icd", &[0x7F, 0xA2, 0x11, 0x9D], true);
        assert!(report.contains("Non-PE32/opaque input"));
        assert!(report.contains("First 4 bytes: 7F A2 11 9D"));
        assert!(report.contains("SHA-256: "));
    }

    #[test]
    fn malformed_mz_does_not_claim_valid_pe() {
        let report = render_report("dplayerx", "synthetic.dll", b"MZbroken", false);
        assert!(report.contains("MZ header present; x86 PE32 metadata unavailable"));
        assert!(!report.contains("PE32 x86 entry RVA"));
    }

    #[test]
    fn synthetic_valid_pe_preserves_section_reporting() {
        let mut data = vec![0u8; 0x400];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x84..0x86].copy_from_slice(&0x14Cu16.to_le_bytes());
        data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
        data[0x98..0x9A].copy_from_slice(&0x10Bu16.to_le_bytes());
        data[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes());
        data[0x178..0x17D].copy_from_slice(b".text");
        data[0x180..0x184].copy_from_slice(&0x100u32.to_le_bytes());
        data[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes());
        data[0x188..0x18C].copy_from_slice(&0x200u32.to_le_bytes());
        data[0x18C..0x190].copy_from_slice(&0x200u32.to_le_bytes());
        let report = render_report("loader", "synthetic.exe", &data, true);
        assert!(report.contains("PE32 x86 entry RVA: 0x00001000; sections: 1"));
        assert!(report.contains(".text: RVA=0x00001000"));
    }
}
