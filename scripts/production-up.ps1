# Windows PowerShell 5.1+; Docker Desktop must use Linux containers.
[CmdletBinding()]
param(
    [switch]$Sync,
    [ValidateRange(30, 3600)][int]$WaitSeconds = 600
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $RepoRoot '.env.production'
$ComposeFile = Join-Path $RepoRoot 'docker-compose.actions.yml'
$ComposeArgs = @('compose', '--env-file', $EnvFile, '-f', $ComposeFile)

try {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw 'Docker CLI was not found. Start Docker Desktop, then open a new PowerShell window.'
    }
    $EngineType = & docker info --format '{{.OSType}}' 2>$null
    if ($LASTEXITCODE -ne 0 -or ($EngineType -join '').Trim() -ne 'linux') {
        throw 'Docker Linux Engine is not ready. Wait for Docker Desktop Engine running; switch to Linux containers if needed.'
    }
    & docker compose version --short 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Docker Compose V2 is required. Update Docker Desktop.' }

    if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
        Copy-Item -LiteralPath (Join-Path $RepoRoot '.env.production.example') -Destination $EnvFile
        throw 'Created .env.production. Fill GITHUB_TOKEN locally (this repository, Actions: read, Metadata: read), save it, then run this command again. Never send the token to chat.'
    }
    # Do not print this file or Compose's resolved configuration: both may hold secrets.
    $TokenEntry = Get-Content -LiteralPath $EnvFile |
        Where-Object { $_ -match '^\s*(?:export\s+)?GITHUB_TOKEN\s*=' } |
        Select-Object -Last 1
    $DeclaredValue = if ($null -ne $TokenEntry) { ($TokenEntry -replace '^\s*(?:export\s+)?GITHUB_TOKEN\s*=\s*', '').Trim() } else { '' }
    if ($DeclaredValue -in @('', '""', "''") -or $DeclaredValue.StartsWith('#')) {
        throw 'Fill GITHUB_TOKEN in your local .env.production before starting Actions pull mode. Do not put the token on the command line.'
    }
    $ResolvedConfig = & docker @ComposeArgs config --format json 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Compose configuration is invalid. Check the local .env.production syntax without sharing its contents.' }
    try { $Config = ($ResolvedConfig -join "`n") | ConvertFrom-Json }
    catch { throw 'Compose configuration could not be parsed. Its secret-bearing contents were not printed.' }
    if ([string]::IsNullOrWhiteSpace([string]$Config.services.'b-mirror'.environment.GITHUB_TOKEN)) {
        throw 'Compose could not load GITHUB_TOKEN. Check .env.production and any existing GITHUB_TOKEN environment override.'
    }
    # Drop the in-memory resolved secret-bearing configuration before build output.
    $ResolvedConfig = $null; $Config = $null; $TokenEntry = $null; $DeclaredValue = $null

    $Other = & docker ps -q --filter 'label=com.docker.compose.project=ai-sec-intel-production' 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect running Docker containers.' }
    if ($Other) { throw 'The collector production project is already running. Stop that project first; keep its data volumes.' }
    $OwnPorts = & docker ps --filter 'label=com.docker.compose.project=ai-sec-intel-actions' --format '{{.Ports}}' 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect existing Actions containers.' }
    foreach ($Port in @(8023, 8765)) {
        if (($OwnPorts -join ' ') -match "127\.0\.0\.1:$Port->") { continue }
        $Listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
        try { $Listener.Start() }
        catch { throw "Port $Port is already in use. Stop the application using it before deployment; do not delete data volumes." }
        finally { $Listener.Stop() }
    }

    Write-Host 'Building and starting the Actions pull deployment; existing data volumes are preserved.'
    & docker @ComposeArgs up -d --build
    if ($LASTEXITCODE -ne 0) { throw 'Docker build/start failed. Existing data volumes have been preserved.' }
    & (Join-Path $PSScriptRoot 'production-check.ps1') -Sync:$Sync -WaitSeconds $WaitSeconds
    if ($LASTEXITCODE -ne 0) { throw 'Deployment started, but end-to-end verification did not pass. Follow the diagnostic instructions above.' }
    Write-Host 'Open http://127.0.0.1:8023. Keep Docker Desktop and this computer running to serve the application.'
}
catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
}
