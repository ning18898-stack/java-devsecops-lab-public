# Dot-source to load lab credentials into this process only.
$ErrorActionPreference = 'Stop'
$labVulnRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
try {
    $labVulnNames = @('VULN001_DB_PASSWORD', 'VULN001_ROOT_PASSWORD')
    $labVulnLoaded = @()
    foreach ($labVulnLine in Get-Content -LiteralPath (Join-Path $labVulnRoot '.env.vuln001')) {
        if ($labVulnLine -match '^([A-Z0-9_]+)=([a-f0-9]{48})$' -and $Matches[1] -in $labVulnNames) {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
            $labVulnLoaded += $Matches[1]
        } else { throw 'Invalid local lab configuration' }
    }
    if ($labVulnLoaded.Count -ne 2 -or @($labVulnLoaded | Select-Object -Unique).Count -ne 2) {
        throw 'Missing or duplicate lab variable'
    }
    $labVulnMessage = "$(Get-Date -Format o) Loaded two VULN-001 variables; exit code 0"
    Write-Output $labVulnMessage
    Add-Content (Join-Path $labVulnRoot 'artifacts/vuln001-env.log') $labVulnMessage
} catch {
    Add-Content (Join-Path $labVulnRoot 'artifacts/vuln001-env.log') "$(Get-Date -Format o) Lab environment load failed; exit code 1"
    throw
}
