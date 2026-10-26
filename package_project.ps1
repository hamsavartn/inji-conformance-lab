# Packaging script for MOSIP Inji Conformance Lab
# Builds mosip_inji_conformance_lab.zip with the CORRECT directory structure
# (the previous recursive file-list approach flattened every file to the archive
#  root, colliding server.js/package.json copies and losing all subdirectories).
#
# Method: stage a clean copy via robocopy (with directory/file exclusions),
# then Compress-Archive the staging root so relative paths are preserved.

$ErrorActionPreference = "Stop"
$Destination = "mosip_inji_conformance_lab.zip"
$Staging = "package_staging"

if (Test-Path $Destination) { Remove-Item $Destination -Force }
if (Test-Path $Staging) { Remove-Item $Staging -Recurse -Force }

# Directories to exclude entirely
$ExcludeDirs = @(
    "node_modules", "dist", ".git", ".qodo", ".gemini", ".playwright-mcp",
    ".zcode", ".claude", ".agents", "package_staging"
)
# Files to exclude (hackathon briefs, binary DB runtime files, the zip itself)
$ExcludeFiles = @(
    "*.db", "*.db-shm", "*.db-wal", "*.zip", "*.docx",
    "mosip_inji_conformance_lab.zip"
)

Write-Host "Staging clean project tree..." -ForegroundColor Cyan
robocopy . $Staging /E /NFL /NDL /NJH /NJS /NP /XD @ExcludeDirs /XF @ExcludeFiles
if ($LASTEXITCODE -ge 8) {
    Write-Host "robocopy failed with code $LASTEXITCODE" -ForegroundColor Red
    exit 1
}

Write-Host "Compressing staged tree into $Destination..." -ForegroundColor Cyan
Compress-Archive -Path (Join-Path $Staging "*") -DestinationPath $Destination -CompressionLevel Optimal -Force

Remove-Item $Staging -Recurse -Force

$Zip = Get-Item $Destination
Write-Host "Package complete: $($Zip.Name) ($([math]::Round($Zip.Length/1MB,2)) MB)" -ForegroundColor Green

# Post-condition: the critical paths MUST exist with directory structure
# (Compress-Archive on Windows stores separators as backslashes — normalize before comparing)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$Archive = [IO.Compression.ZipFile]::OpenRead($Zip.FullName)
$Names = $Archive.Entries | ForEach-Object { $_.FullName -replace '\\', '/' }
$Archive.Dispose()
$Required = @(
    "backend/server.js",
    "mocks/issuer/server.js",
    "mocks/verifier/server.js",
    "frontend/src/App.tsx",
    "scripts/test_e2e_local.js",
    "scripts/test_security_regression.js",
    "docs/DEMO_VIDEO_SCRIPT.md",
    "docs/verification-matrix.md",
    "AUDIT_REPORT.md",
    "SUBMISSION_CHECKLIST.md",
    "JUDGE_TESTING_GUIDE.md",
    "LICENSE",
    "README.md",
    "PITCH_DECK.pptx",
    "docker-compose.yml",
    ".github/workflows/interop-matrix.yml"
)
$Missing = $Required | Where-Object { $Names -notcontains $_ }
if ($Missing.Count -gt 0) {
    Write-Host "VERIFICATION FAILED - missing from zip: $($Missing -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "Verified: all $($Required.Count) critical deliverables present with correct paths." -ForegroundColor Green
