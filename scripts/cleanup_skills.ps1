# Script to remove extraneous agent folders created by npx skills and keep only .agents
$unwantedDirs = @(
  '.adal', '.aider-desk', '.augment', '.autohand', '.bob', '.claude', '.codeartsdoer',
  '.codebuddy', '.codemaker', '.codestudio', '.commandcode', '.continue', '.cortex',
  '.crush', '.devin', '.forge', '.goose', '.grok', '.hermes', '.iflow', '.inferencesh',
  '.jazz', '.junie', '.kimchi', '.kiro', '.kode', '.lingma', '.mcpjam', '.minimax',
  '.moxby', '.mux', '.neovate', '.ona', '.openhands', '.pochi', '.posit', '.qoder',
  '.qwen', '.reasonix', '.roo', '.rovodev', '.tabnine', '.terramind', '.tinycloud',
  '.trae', '.vibe', '.windsurf', '.zcode', '.zencoder', 'agent', 'data', 'skills'
)

foreach ($dir in $unwantedDirs) {
  if (Test-Path $dir) {
    Remove-Item -Recurse -Force $dir
    Write-Host "Removed extraneous directory: $dir" -ForegroundColor Yellow
  }
}

# Now clean up .agents/skills to keep strictly the top 10 relevant skills
$keepSkills = @(
  'find-skills',
  'vercel-react-best-practices',
  'web-design-guidelines',
  'test-driven-development',
  'security-and-hardening',
  'ci-cd-and-automation',
  'api-and-interface-design',
  'observability-and-instrumentation',
  'performance-optimization',
  'browser-testing-with-devtools'
)

$allSkills = Get-ChildItem -Path ".agents\skills" -Directory
foreach ($s in $allSkills) {
  if ($keepSkills -notcontains $s.Name) {
    Remove-Item -Recurse -Force $s.FullName
    Write-Host "Removed irrelevant skill: $($s.Name)" -ForegroundColor Cyan
  } else {
    Write-Host "Kept relevant skill: $($s.Name)" -ForegroundColor Green
  }
}
