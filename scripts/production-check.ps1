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
from deployment.actions_state import GitHubClient, StateError
try:
    repository = os.environ.get("GITHUB_REPOSITORY", "sijunxiaodeng/ai-sec-intel")
    run, artifact = latest_snapshot(GitHubClient(os.environ.get("GITHUB_TOKEN"), repository))
    run_id, commit = run.get("id"), run.get("head_sha")
    if type(run_id) is not int or run_id <= 0 or not re.fullmatch(r"[0-9a-f]{40}", str(commit)):
        raise ValueError()
    print(json.dumps({"run_id": run_id, "collector_commit": commit}))
except StateError as exc:
    message = str(exc)
    status = re.fullmatch(r"GitHub state API failed: HTTP ([1-5][0-9]{2}); no collection was started", message)
    http_status = int(status.group(1)) if status else None
    if message == "GitHub state API unavailable; no collection was started":
        category = "github_network_unavailable"
    elif http_status == 401:
        category = "github_authentication_failed"
    elif http_status == 403:
        category = "github_access_denied_or_rate_limited"
    elif http_status == 429:
        category = "github_rate_limited"
    elif http_status is not None and http_status >= 500:
        category = "github_http_unavailable"
    elif http_status is not None:
        category = "github_resource_unavailable"
    else:
        category = "snapshot_metadata_unverified"
    print(json.dumps({"error_category": category, "http_status": http_status}))
    sys.exit(1)
except Exception:
    print(json.dumps({"error_category": "unexpected_metadata_failure"}))
    sys.exit(1)
'@
    Write-Host 'Reading the latest trusted Actions metadata from GitHub.'
    $MetadataJson = $MetadataCode | & docker @ComposeArgs exec -T b-mirror python -
    $MetadataExitCode = $LASTEXITCODE
    try { $Metadata = ($MetadataJson -join "`n") | ConvertFrom-Json }
    catch { throw 'Latest Actions metadata response was invalid; its contents were not printed.' }
    if ($MetadataExitCode -ne 0 -or $Metadata.error_category) {
        $SafeCategories = @('github_network_unavailable', 'github_authentication_failed',
            'github_access_denied_or_rate_limited', 'github_rate_limited', 'github_http_unavailable',
            'github_resource_unavailable', 'snapshot_metadata_unverified', 'unexpected_metadata_failure')
        $Category = if ([string]$Metadata.error_category -in $SafeCategories) { [string]$Metadata.error_category } else { 'metadata_unverified' }
        $HttpHint = if (($Metadata.http_status -is [int] -or $Metadata.http_status -is [long]) -and $Metadata.http_status -ge 100 -and $Metadata.http_status -le 599) { " (HTTP $($Metadata.http_status))" } else { '' }
        throw "Latest Actions metadata could not be verified: $Category$HttpHint. No successful deployment claim was made."
    }
    $RunId = [long]$Metadata.run_id
    $Commit = [string]$Metadata.collector_commit
    if ($RunId -le 0 -or $Commit -notmatch '^[0-9a-f]{40}$') { throw 'Actions metadata response was invalid.' }
    Write-Host "Verifying real Actions run $RunId ($Commit), snapshot serving and both durable consumers."
    Write-Host "Waiting for snapshot download/import (about $WaitSeconds seconds; an active request may finish later)."
    Write-Host 'To inspect progress in another PowerShell window: docker compose --env-file .env.production -f docker-compose.actions.yml logs --tail 40 b-mirror'
    $CheckArgs = @('exec', '-T', 'main-app', 'python', 'scripts/deployment_check.py',
        '--run-id', [string]$RunId, '--collector-commit', $Commit, '--wait-seconds', [string]$WaitSeconds,
        '--progress', '--output', '/app/data/deployment-proof.json')
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
