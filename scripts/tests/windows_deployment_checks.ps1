# Isolated native-command checks; no Docker daemon, GitHub or real token used.
# CI runs this under Windows PowerShell 5.1. Linux pwsh can also check the mocks.
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$FixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ai-sec-windows-checks-' + [Guid]::NewGuid().ToString('N'))
$BinDir = Join-Path $FixtureRoot 'bin'
$OriginalPath = $env:PATH
$TestEnvNames = @('AISEC_TEST_CASE', 'AISEC_TEST_CALLS', 'AISEC_TEST_PWSH', 'AISEC_TEST_MOCK_SCRIPT')
$OriginalTestEnv = @{}
foreach ($Name in $TestEnvNames) { $OriginalTestEnv[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process') }
$IsWindowsHost = [System.IO.Path]::DirectorySeparatorChar -eq '\'
$PowerShellExe = Join-Path $PSHOME $(if ($IsWindowsHost) { 'powershell.exe' } else { 'pwsh' })
$FixtureSecret = 'fixture-secret-never-print'

try {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    $MockScript = Join-Path $BinDir 'mock-docker.ps1'
    $MockCode = @'
$DockerArgs = @($args | ForEach-Object { if ($_ -eq '__AISEC_STDIN_DASH__') { '-' } else { $_ } })
Add-Content -LiteralPath $env:AISEC_TEST_CALLS -Encoding UTF8 -Value (ConvertTo-Json -Compress -InputObject $DockerArgs)
$Case = $env:AISEC_TEST_CASE
if ($DockerArgs[0] -eq 'info') {
    if ($Case -eq 'wrong-engine') { Write-Output 'windows' } else { Write-Output 'linux' }
    exit 0
}
if ($DockerArgs[0] -eq 'compose' -and $DockerArgs[1] -eq 'version') { Write-Output 'v2.30.0'; exit 0 }
if ($DockerArgs[0] -eq 'ps') {
    if ($DockerArgs -contains '-q') {
        if ($Case -eq 'other-project') { Write-Output 'existing-collector' }
    } elseif ($Case -ne 'port-conflict') {
        Write-Output '127.0.0.1:8023->8023/tcp, 127.0.0.1:8765->8765/tcp'
    }
    exit 0
}
if ($DockerArgs -contains 'config') {
    if ($Case -eq 'invalid-config') { Write-Output '{invalid json fixture-secret-never-print'; exit 0 }
    Write-Output '{"services":{"b-mirror":{"environment":{"GITHUB_TOKEN":"fixture-secret-never-print"}}}}'
    exit 0
}
if ($DockerArgs -contains 'up') { if ($Case -eq 'build-fail') { exit 1 }; exit 0 }
if ($DockerArgs -contains 'exec' -and $DockerArgs -contains 'b-mirror') {
    $InputCode = [Console]::In.ReadToEnd()
    if (-not $InputCode.Contains('from deployment.actions_mirror import latest_snapshot')) { exit 3 }
    @{ run_id = [long]38515772960; collector_commit = ('a' * 40) } | ConvertTo-Json -Compress
    exit 0
}
if ($DockerArgs -contains 'exec' -and $DockerArgs -contains 'main-app') {
    if (($DockerArgs -contains '--synchronize') -ne ($Case -ne 'read-only')) { exit 3 }
    foreach ($Expected in @('scripts/deployment_check.py', '--run-id', '38515772960', '--collector-commit', ('a' * 40), '--output', '/app/data/deployment-proof.json')) {
        if (-not ($DockerArgs -contains $Expected)) { exit 3 }
    }
    Write-Output '{"snapshot_serving_verified":true,"consumption_verified":true,"deployment_import_loop_verified":true,"processing_verified":false}'
    if ($Case -eq 'check-fail') { exit 1 }; exit 0
}
exit 3
'@
    Set-Content -LiteralPath $MockScript -Value $MockCode -Encoding UTF8
    if ($IsWindowsHost) {
        # A .cmd native process preserves the actual external-command exit code.
        # Windows powershell.exe -File treats a lone '-' as an invalid empty
        # parameter name before the mock can run. Docker.exe accepts it as stdin.
        # Encode only this fixed mock argument and restore it inside the script.
        $MockLauncher = '@echo off' + "`r`nsetlocal`r`n" + 'set "AISEC_NATIVE_ARGUMENTS=%*"' + "`r`n" +
            'set "AISEC_NATIVE_ARGUMENTS=%AISEC_NATIVE_ARGUMENTS:python -=python __AISEC_STDIN_DASH__%"' + "`r`n" +
            '"' + $PowerShellExe + '" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0mock-docker.ps1" %AISEC_NATIVE_ARGUMENTS%' + "`r`nexit /b %errorlevel%`r`n"
        Set-Content -LiteralPath (Join-Path $BinDir 'docker.cmd') -Value $MockLauncher -Encoding Ascii
    } else {
        $env:AISEC_TEST_PWSH = $PowerShellExe
        $env:AISEC_TEST_MOCK_SCRIPT = $MockScript
        Set-Content -LiteralPath (Join-Path $BinDir 'docker') -Value ('#!/bin/sh' + "`n" + 'exec "$AISEC_TEST_PWSH" -NoLogo -NoProfile -File "$AISEC_TEST_MOCK_SCRIPT" "$@"') -Encoding Ascii
        & chmod +x (Join-Path $BinDir 'docker')
        if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the isolated native mock.' }
    }
    $env:PATH = $BinDir + [System.IO.Path]::PathSeparator + $OriginalPath
    $ResolvedDocker = Get-Command docker -CommandType Application -ErrorAction Stop
    if (-not $ResolvedDocker.Source.StartsWith($BinDir + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to run: Docker did not resolve to the isolated native mock.'
    }

    $Cases = @(
        @{ Name = 'happy'; Expected = 0 },
        @{ Name = 'missing-env'; Expected = 1 },
        @{ Name = 'empty-token'; Expected = 1 },
        @{ Name = 'invalid-config'; Expected = 1 },
        @{ Name = 'wrong-engine'; Expected = 1 },
        @{ Name = 'other-project'; Expected = 1 },
        @{ Name = 'build-fail'; Expected = 1 },
        @{ Name = 'check-fail'; Expected = 1 },
        @{ Name = 'port-conflict'; Expected = 1 },
        @{ Name = 'read-only'; Expected = 0 }
    )
    foreach ($Case in $Cases) {
        # Space in the path checks argument quoting used by both launchers.
        $CaseRoot = Join-Path $FixtureRoot ('case ' + $Case.Name)
        $CaseScripts = Join-Path $CaseRoot 'scripts'
        New-Item -ItemType Directory -Path $CaseScripts -Force | Out-Null
        foreach ($File in @('production-up.ps1', 'production-check.ps1')) {
            Copy-Item -LiteralPath (Join-Path $RepoRoot ('scripts/' + $File)) -Destination $CaseScripts
        }
        Set-Content -LiteralPath (Join-Path $CaseRoot '.env.production.example') -Value 'GITHUB_TOKEN=' -Encoding Ascii
        Set-Content -LiteralPath (Join-Path $CaseRoot 'docker-compose.actions.yml') -Value 'services: {}' -Encoding Ascii
        if ($Case.Name -ne 'missing-env') {
            $TokenLine = if ($Case.Name -eq 'empty-token') { 'GITHUB_TOKEN=' } else { 'GITHUB_TOKEN=' + $FixtureSecret }
            Set-Content -LiteralPath (Join-Path $CaseRoot '.env.production') -Value $TokenLine -Encoding Ascii
        }
        $env:AISEC_TEST_CASE = $Case.Name
        $env:AISEC_TEST_CALLS = Join-Path $CaseRoot 'calls.jsonl'
        New-Item -ItemType File -Path $env:AISEC_TEST_CALLS -Force | Out-Null
        $Entry = if ($Case.Name -eq 'read-only') { 'production-check.ps1' } else { 'production-up.ps1' }
        $Arguments = @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + (Join-Path $CaseScripts $Entry) + '"'))
        if ($Case.Name -ne 'read-only') { $Arguments += '-Sync' }
        $Arguments += @('-WaitSeconds', '40')
        $Stdout = Join-Path $CaseRoot 'stdout.txt'; $Stderr = Join-Path $CaseRoot 'stderr.txt'
        $Listener = $null
        try {
            if ($Case.Name -eq 'port-conflict') {
                $Listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 8023)
                try { $Listener.Start() } catch { $Listener.Stop(); $Listener = $null }
                # If already occupied, the same rejection remains expected.
            }
            $Process = Start-Process -FilePath $PowerShellExe -ArgumentList $Arguments -PassThru -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr
            [void]$Process.Handle
            if (-not $Process.WaitForExit(60000)) { $Process.Kill(); throw ('Mock timed out: ' + $Case.Name) }
            $Process.Refresh()
            $Output = [System.IO.File]::ReadAllText($Stdout) + [System.IO.File]::ReadAllText($Stderr)
            if ($Output.Contains($FixtureSecret)) { throw ('Secret appeared in output: ' + $Case.Name) }
            if ($Process.ExitCode -ne $Case.Expected) {
                # This fixture cannot call real Docker and the secret check ran
                # first. Preserve safe native-host diagnostics for platform bugs.
                throw ('Unexpected exit code: ' + $Case.Name + ' (' + $Process.ExitCode + ')' + "`n" + $Output)
            }
            $Calls = @(Get-Content -LiteralPath $env:AISEC_TEST_CALLS | ForEach-Object { ,($_ | ConvertFrom-Json) })
            foreach ($Call in $Calls) {
                if ($Call -contains 'down' -or $Call -contains '-v' -or $Call -contains '--volumes' -or ($Call -contains 'volume' -and $Call -contains 'rm')) {
                    throw ('Destructive Docker operation: ' + $Case.Name)
                }
            }
            if ($Case.Name -in @('missing-env', 'empty-token', 'invalid-config', 'wrong-engine', 'other-project', 'port-conflict')) {
                if (@($Calls | Where-Object { $_ -contains 'up' }).Count) { throw ('Started despite failed prerequisite: ' + $Case.Name) }
            }
            if ($Case.Name -eq 'happy' -or $Case.Name -eq 'read-only') {
                if (-not @($Calls | Where-Object { $_ -contains 'scripts/deployment_check.py' }).Count) { throw ('No delivery proof invoked: ' + $Case.Name) }
            }
            if ($Case.Name -eq 'read-only' -and @($Calls | Where-Object { $_ -contains '--synchronize' }).Count) { throw 'Read-only check requested synchronization.' }
            if ($Case.Name -eq 'missing-env' -and -not (Test-Path -LiteralPath (Join-Path $CaseRoot '.env.production'))) { throw 'Missing environment template was not prepared.' }
            Write-Output ('PASS: ' + $Case.Name)
        }
        finally { if ($null -ne $Listener) { $Listener.Stop() } }
    }
    Write-Output ('PASS: ' + $Cases.Count + ' isolated deployment checks; no Docker daemon or real credentials used.')
}
finally {
    $env:PATH = $OriginalPath
    foreach ($Name in $TestEnvNames) { [Environment]::SetEnvironmentVariable($Name, $OriginalTestEnv[$Name], 'Process') }
    if (Test-Path -LiteralPath $FixtureRoot) { Remove-Item -LiteralPath $FixtureRoot -Recurse -Force }
}
