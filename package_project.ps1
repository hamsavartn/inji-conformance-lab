# Packaging script for MOSIP Inji Conformance Lab
$Destination = "mosip_inji_conformance_lab.zip"
if (Test-Path $Destination) {
    Remove-Item $Destination -Force
}

# Explicitly target project source directories and core files
$IncludePatterns = @(
    "backend\*",
    "frontend\src\*",
    "frontend\index.html",
    "frontend\package.json",
    "frontend\tsconfig.json",
    "frontend\vite.config.ts",
    "mocks\*",
    "fixtures\*",
    "scripts\*",
    "db\*",
    ".github\*",
    ".agents\skills\*",
    "*.md",
    "*.yaml",
    "*.yml",
    "*.json",
    "package_project.ps1"
)

$FilesToZip = Get-ChildItem -Path . -Recurse | Where-Object {
    $path = $_.FullName
    # Exclude node_modules, dist, git, zip, and docx
    if ($path -like "*\node_modules\*" -or $path -like "*/node_modules/*") { return $false }
    if ($path -like "*\dist\*" -or $path -like "*/dist/*") { return $false }
    if ($path -like "*\.qodo\*" -or $path -like "*/.qodo/*") { return $false }
    if ($path -like "*\.git\*" -or $path -like "*/.git/*") { return $false }
    if ($path -like "*\.gemini\*" -or $path -like "*/.gemini/*") { return $false }
    if ($_.Name -eq $Destination -or $_.Name -like "*.docx") { return $false }
    
    # Exclude other agent subdirectories except .agents
    if ($_.FullName -match '\\\.(aider|autohand|augment|bob|claude|code|continue|cortex|crush|devin|forge|goose|grok|hermes|iflow|inference|jazz|junie|kimchi|kiro|kode|lingma|mcpjam|minimax|moxby|mux|neovate|ona|openhands|pochi|posit|qoder|qwen|reasonix|roo|rovodev|tabnine|terramind|tinycloud|trae|vibe|windsurf|zcode|zencoder|adal)\\') {
        return $false
    }
    
    return -not $_.PSIsContainer
}

Write-Host "Compressing $($FilesToZip.Count) clean source items into $Destination..." -ForegroundColor Cyan
Compress-Archive -Path $FilesToZip.FullName -DestinationPath $Destination -CompressionLevel Optimal -Force
Write-Host "Package complete: $Destination" -ForegroundColor Green
Get-Item $Destination | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
