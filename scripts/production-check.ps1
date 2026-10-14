# No local Python or GitHub CLI is required; secrets stay in b-mirror.
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
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker CLI was not found.' }
    if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) { throw 'Local .env.production is missing. Run scripts/production-up.ps1 first.' }
    $EngineType = & docker info --format '{{.OSType}}' 2>$null
    if ($LASTEXITCODE -ne 0 -or ($EngineType -join '').Trim() -ne 'linux') { throw 'Docker Linux Engine is not running.' }

    # Bind the expected generation to GitHub metadata, independently of the API
    # generation currently being served. Only run ID / SHA leave this container.
    $MetadataCode = @'
import json, os, re, sys
from deployment.actions_mirror import latest_snapshot
from deployment.actions_state import GitHubClient
try:
    repository = os.environ.get("GITHUB_REPOSITORY", "sijunxiaodeng/ai-sec-intel")
    run, artifact = latest_snapshot(GitHubClient(os.environ.get("GITHUB_TOKEN"), repository))
    run_id, commit = run.get("id"), run.get("head_sha")
    if type(run_id) is not int or run_id <= 0 or not re.fullmatch(r"[0-9a-f]{40}", str(commit)):
        raise ValueError()
    print(json.dumps({"run_id": run_id, "collector_commit": commit}))
except Exception:
    print("Could not establish the latest trusted Actions generation. Check token permissions, network and collector workflow status.", file=sys.stderr)
    sys.exit(1)
'@
    $MetadataJson = $MetadataCode | & docker @ComposeArgs exec -T b-mirror python -
    if ($LASTEXITCODE -ne 0) { throw 'Latest Actions metadata could not be verified; no successful deployment claim was made.' }
    $Metadata = ($MetadataJson -join "`n") | ConvertFrom-Json
    $RunId = [long]$Metadata.run_id
    $Commit = [string]$Metadata.collector_commit
    if ($RunId -le 0 -or $Commit -notmatch '^[0-9a-f]{40}$') { throw 'Actions metadata response was invalid.' }
    Write-Host "Verifying real Actions run $RunId ($Commit), snapshot serving and both durable consumers."
    $CheckArgs = @('exec', '-T', 'main-app', 'python', 'scripts/deployment_check.py',
        '--run-id', [string]$RunId, '--collector-commit', $Commit, '--wait-seconds', [string]$WaitSeconds,
        '--output', '/app/data/deployment-proof.json')
    if ($Sync) { $CheckArgs += '--synchronize' }
    & docker @ComposeArgs @CheckArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'To inspect deployment state: docker compose --env-file .env.production -f docker-compose.actions.yml ps'
        Write-Host 'For safe mirror diagnostics: docker compose --env-file .env.production -f docker-compose.actions.yml logs --tail 60 b-mirror'
        throw 'End-to-end verification is incomplete. Keep existing data volumes; fix the reported reason and rerun production-check.ps1 -Sync.'
    }
}
catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
}
