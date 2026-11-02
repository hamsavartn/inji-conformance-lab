# Packaging script for MOSIP Inji Conformance Lab
# Builds mosip_inji_conformance_lab.zip with clean directory structure
# and verified submission assets, strictly excluding all non-relevant files.

$ErrorActionPreference = "Stop"
$Destination = "mosip_inji_conformance_lab.zip"
$Staging = "package_staging"

if (Test-Path $Destination) { Remove-Item $Destination -Force }
if (Test-Path $Staging) { Remove-Item $Staging -Recurse -Force }

# Directories to exclude entirely
$ExcludeDirs = @(
    "node_modules", "dist", ".git", ".qodo", ".gemini", ".playwright-mcp",
    ".zcode", ".claude", ".agents", "package_staging", "scratch",
    ".vscode", ".idea"
)

# Files to exclude (runtime DBs, unneeded zips, scratch binaries, non-hackathon agent files)
$ExcludeFiles = @(
    "*.db", "*.db-shm", "*.db-wal", "*.zip", "*.docx",
    "mosip_inji_conformance_lab.zip",
    "*AUDIT_PROMPT*.md", "*AUDIT_MANDATE*.md", "FINAL_JUDICIAL_AUDIT_REPORT.md",
    "DEMO_VIDEO_SCRIPT.md", "blueprint_raw.txt", "extract_docx.py",
    "fouriertherm*.png", "ieee_paper_preview.png",
    "memory.md", "tasks.md", "skills-lock.json", "cleanup_skills.ps1"
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

# Copy to submission_deliverables folder
$DeliverablesZipPath = "submission_deliverables/07_packaged_zip_deliverables/$Destination"
if (Test-Path "submission_deliverables/07_packaged_zip_deliverables") {
    Copy-Item $Destination $DeliverablesZipPath -Force
    Write-Host "Copied package to: $DeliverablesZipPath" -ForegroundColor Green
}

# Post-condition: verify all critical submission assets exist in the archive
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
    "scripts/test_mdoc_tamper_and_replay.js",
    "docs/verification-matrix.md",
    "docs/screenshots/ui_main_dashboard.jpg",
    "docs/screenshots/ui_interop_matrix.jpg",
    "fixtures/TEST_DATA.md",
    "openapi_spec.yaml",
    "AUDIT_REPORT.md",
    "SUBMISSION_CHECKLIST.md",
    "JUDGE_TESTING_GUIDE.md",
    "LICENSE",
    "README.md",
    "PITCH_DECK.pptx",
    "PITCH_DECK.pdf",
    "docker-compose.yml",
    "Dockerfile",
    "railway.json",
    "docs/RAILWAY_DEPLOYMENT_GUIDE.md",
    ".github/workflows/interop-matrix.yml",
    "submission_deliverables/01_pitch_presentation_or_slide_deck/PITCH_DECK.pdf",
    "submission_deliverables/02_design_mockup_and_wireframe/design.md",
    "submission_deliverables/03_architecture_diagram/architecture.md",
    "submission_deliverables/04_test_data_and_results/TEST_DATA.md",
    "submission_deliverables/05_usage_and_installation_instructions/README.md",
    "submission_deliverables/06_api_documentation/openapi_spec.yaml"
)

$Missing = $Required | Where-Object { $Names -notcontains $_ }
if ($Missing.Count -gt 0) {
    Write-Host "VERIFICATION FAILED - missing from zip: $($Missing -join ', ')" -ForegroundColor Red
    exit 1
}

# Verify NO forbidden/unnecessary files slipped into the zip
$ForbiddenMatches = $Names | Where-Object {
    $_ -match 'AUDIT_PROMPT' -or
    $_ -match 'AUDIT_MANDATE' -or
    $_ -match 'DEMO_VIDEO_SCRIPT' -or
    $_ -match 'fouriertherm' -or
    $_ -match '\.docx$' -or
    $_ -match 'blueprint_raw' -or
    $_ -match 'memory\.md$' -or
    $_ -match 'tasks\.md$'
}

if ($ForbiddenMatches.Count -gt 0) {
    Write-Host "VERIFICATION FAILED - forbidden files found in zip: $($ForbiddenMatches -join ', ')" -ForegroundColor Red
    exit 1
}

Write-Host "Package Verification Passed: All $($Required.Count) required assets present. 0 unnecessary files." -ForegroundColor Green
