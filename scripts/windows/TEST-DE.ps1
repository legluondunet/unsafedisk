# Crimson Skies German retail 1.0.0.1 -- owned CD pair only.
# Run beside unsafedisc-linux.exe and original CRIMSON.EXE / CRIMSON.ICD.
# Original filenames are not required; sources are authenticated by SHA-256.
$ErrorActionPreference = 'Stop'
$folder = $PSScriptRoot
$logPath = Join-Path $folder 'TEST-DE.log'
$tool = Join-Path $folder 'unsafedisc-linux.exe'
$output = Join-Path $folder 'CRIMSON-DE-100-CANDIDATE.EXE'
$expectedLoaderHash = 'a4ba27ae4070952611872f3120ab5859469691ad0954203a83dbfe2f2e0750af'
$expectedIcdHash = '5fb33f3bdc6977283620fe2bfe4f1cc734cf64ef6cec844e8f983e25986b7172'
$expectedOutputHash = '11242994ee568065a30fcfcfa1c9c23f86d60ea56f937bb00648bf9558fa1e70'
Set-Content -LiteralPath $logPath -Encoding UTF8 -Value @(
    'TEST-DE: original German Crimson Skies 1.00 reconstruction',
    ('Directory: ' + $folder),
    ('Date: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')),
    'The original protected CD files are not modified.'
)
function Write-TestLog([string]$message) {
    Write-Host $message
    Add-Content -LiteralPath $logPath -Encoding UTF8 -Value $message
}
function Find-OriginalFile([string]$extension, [long]$size, [string]$hash, [string]$label) {
    $foundFiles = @(
        Get-ChildItem -LiteralPath $folder -File -ErrorAction Stop |
            Where-Object { $_.Extension -ieq $extension -and $_.Length -eq $size } |
            Where-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash -ieq $hash }
    )
    if ($foundFiles.Count -ne 1) {
        throw ("{0}: {1} valid file(s) found in '{2}'; exactly one required (extension {3}, size {4}, SHA-256 {5}). Copy the original DE CD file here, even if Windows renamed it." -f $label, $foundFiles.Count, $folder, $extension, $size, $hash)
    }
    return $foundFiles[0]
}
try {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        throw "Executable not found: '$tool'. Extract the complete Windows artifact into one folder."
    }
    Write-TestLog ('Tool: ' + $tool)
    $loader = Find-OriginalFile '.exe' 344993 $expectedLoaderHash 'German loader'
    $icd = Find-OriginalFile '.icd' 2560095 $expectedIcdHash 'German ICD'
    Write-TestLog ('Authenticated loader: ' + $loader.FullName)
    Write-TestLog ('Authenticated ICD: ' + $icd.FullName)
    if (Test-Path -LiteralPath $output) {
        throw "Output already exists; refusing to overwrite: '$output'. Move or rename it before another test."
    }
    Write-TestLog ('New output: ' + $output)
    & $tool unwrap-retail100 --loader $loader.FullName --icd $icd.FullName --output $output 2>&1 |
        ForEach-Object { Write-TestLog ([string]$_) }
    $toolExitCode = $LASTEXITCODE
    if ($toolExitCode -ne 0) {
        throw "Native reconstruction failed (exit code $toolExitCode). See lines above."
    }
    if (-not (Test-Path -LiteralPath $output -PathType Leaf)) {
        throw "Native tool returned success but did not create: '$output'"
    }
    $created = Get-Item -LiteralPath $output
    if ($created.Length -ne 2560000) {
        throw "Unexpected output size: $($created.Length) (expected 2560000 bytes)."
    }
    $actualHash = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedOutputHash) {
        throw "Unexpected output SHA-256: $actualHash (expected $expectedOutputHash)."
    }
    Write-TestLog ('SUCCESS: German 1.00 candidate created; SHA-256 ' + $actualHash)
    Write-TestLog 'NOTE: Experimental 1.00 executable, NOT the verified 1.02 runtime accepted by CrimsonSkiesFix.'
    exit 0
} catch {
    Write-TestLog ('ERROR: ' + $_.Exception.Message)
    exit 1
}
