# Repository migration

The SafeDisc/unSafeDisc research files were extracted from `legluondunet/CrimsonSkiesFix` PR #6 branch `feature/crimsonfix-ddraw-proxy-poc` at commit `eb0d7203ca8bd078986b77eafd9ab96e56d23ceb` (2026-10-30).

- Native Rust CLI, reconstruction modules and legacy Crimson Skies patcher: `src/`
- SafeDisc analyses: `docs/`
- Python v0.9 unwrapper and older v0.8: `python/`
- Offline Wine/SafeDisc research helpers: `scripts/`
- Legacy archive: `archive/`
- Research CI: `.github/workflows/`

Source files and research notes are unchanged, except repository-root README and CI relative paths. No copyrighted game executables, protected ICD data, game DLLs, or Win98 memory captures are bundled. The independent CrimsonSkiesFix DirectDraw DLL stays in its original repository.
