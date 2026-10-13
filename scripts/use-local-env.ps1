# Dot-source in the current PowerShell session. Never modify system configuration.
$ErrorActionPreference = 'Stop'
$labEnvRoot = Split-Path -Parent $PSScriptRoot
$labEnvPath = Join-Path $labEnvRoot '.env'
try {
    if (-not (Test-Path -LiteralPath $labEnvPath)) { throw 'Run python scripts/init-local-env.py first' }
    $labAllowedNames = @('DB_PASSWORD', 'MYSQL_ROOT_PASSWORD', 'TEST_DB_PASSWORD', 'MYSQL_TEST_ROOT_PASSWORD')
    $labLoadedNames = @()
    foreach ($labLine in Get-Content -LiteralPath $labEnvPath -Encoding utf8) {
        if ($labLine -match '^([A-Z_]+)=(.*)$' -and $Matches[1] -in $labAllowedNames) {
            if ([string]::IsNullOrWhiteSpace($Matches[2])) { throw 'Empty local database credential' }
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
            $labLoadedNames += $Matches[1]
        }
    }
    if (@($labAllowedNames | Where-Object { $_ -notin $labLoadedNames }).Count -ne 0) { throw 'Missing database credential' }
    $labMessage = "$(Get-Date -Format o) Loaded four local database variables; exit code 0"
    Write-Output $labMessage
    Add-Content -LiteralPath (Join-Path $labEnvRoot 'artifacts/local-env.log') -Value $labMessage
} catch {
    $labMessage = "$(Get-Date -Format o) Local database environment setup failed; exit code 1"
    Write-Output $labMessage
    Add-Content -LiteralPath (Join-Path $labEnvRoot 'artifacts/local-env.log') -Value $labMessage
    throw
}
