// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline native reconstruction API for exact, SHA-pinned Crimson Skies
//! SafeDisc 1.02 editions. Compiled into consumers; no companion executable,
//! historical Windows DLL, internet access or proprietary bytes bundled.
//!
//! Source compatibility: internal API for experimental preservation research.
//! Redistribution or gameplay claims require independent legal/runtime review.


// Include the existing native reconstruction implementation at the crate
// root. Its internal research modules rely on `crate::unsafedisc_*` paths.
include!("bin/unsafedisc-linux.rs");

/// Derive the exact 1.02 executable directly in memory from authenticated
/// original SafeDisc 1.02 bytes (French CD or local official Microsoft update).
/// No protected sources, full updater or decrypted EXE are persisted by this
/// operation. The caller must protect the returned game image as private
/// owner material and verify its final install transaction separately.
pub fn reconstruct_verified_crimson_102_bytes(
    loader:&[u8], icd:&[u8]
)->Result<Vec<u8>>{
    reconstruct_verified_102_in_memory(loader,icd)
}

/// Reconstruct the exact approved PE32 game executable from the original
/// matching 1.02 SafeDisc loader and ICD files already extracted locally.
///
/// The output must not exist: the underlying algorithm verifies the complete
/// SHA-256 before the first output byte is written, uses create_new, and
/// removes incomplete output on write errors. The caller owns the paths and
/// any subsequent installation transaction.
pub fn reconstruct_verified_crimson_102(
    loader: &Path, icd: &Path, new_output: &Path,
) -> Result<()> {
    unwrap_verified_102_files(loader,icd,new_output)
}

#[cfg(test)]
mod native_library_tests {
    use super::*;
    #[test]
    fn unsupported_memory_inputs_fail_closed() {
        assert!(reconstruct_verified_crimson_102_bytes(&[],&[]).is_err());
        assert!(reconstruct_verified_crimson_102_bytes(&[0;344_851],&[0;2_580_578]).is_err());
    }
    #[test]
    fn absent_original_sources_fail_closed() {
        let impossible=std::env::temp_dir().join(format!(
            "unsafedisk-library-no-original-{}-{}.icd",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap().as_nanos()));
        let output=impossible.with_extension("exe");
        assert!(reconstruct_verified_crimson_102(&impossible,&impossible,&output).is_err());
        assert!(!output.exists());
    }
}
