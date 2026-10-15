# Optional Windows download path when the Python TLS client cannot reach Hugging Face.
param([string]$Destination)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$cachePath = if ($Destination) { [System.IO.Path]::GetFullPath($Destination) } else { Join-Path $repoRoot 'data/models/bge-small-zh-v1.5-local' }
$revision = '46fbe35fd4374a00fee7de77dfddaeb6dd6a2c59'
$modelBase = 'https://huggingface.co/Qdrant/bge-small-zh-v1.5'
$metadataUrl = 'https://huggingface.co/api/models/Qdrant/bge-small-zh-v1.5/revision/' + $revision + '?blobs=true'
$metadata = Invoke-RestMethod -Uri $metadataUrl -TimeoutSec 30
if ($metadata.sha -ne $revision) { throw 'Model metadata revision mismatch' }
$files = @('config.json', 'model_optimized.onnx', 'special_tokens_map.json', 'tokenizer.json', 'tokenizer_config.json', 'vocab.txt')
function Test-ModelFile($Path, $Entry) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    if ((Get-Item -LiteralPath $Path).Length -ne $Entry.size) { return $false }
    if ($Entry.lfs.sha256) {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -eq $Entry.lfs.sha256
    }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $header = [System.Text.Encoding]::ASCII.GetBytes(('blob ' + $bytes.Length + [char]0))
    $sha = [System.Security.Cryptography.SHA1]::Create()
    try {
        $actual = [BitConverter]::ToString($sha.ComputeHash($header + $bytes)).Replace('-', '').ToLowerInvariant()
        return $actual -eq $Entry.blobId
    } finally { $sha.Dispose() }
}
New-Item -ItemType Directory -Path $cachePath -Force | Out-Null
foreach ($fileName in $files) {
    $filePath = Join-Path $cachePath $fileName
    $entries = @($metadata.siblings | Where-Object { $_.rfilename -eq $fileName })
    if ($entries.Count -ne 1) { throw ('Missing model metadata: ' + $fileName) }
    $entry = $entries[0]
    if (Test-ModelFile $filePath $entry) { Write-Output ('Cached ' + $fileName); continue }
    Write-Output ('Downloading ' + $fileName)
    $temporaryPath = $filePath + '.' + [guid]::NewGuid().ToString('N') + '.download'
    try {
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Invoke-WebRequest -Uri ($modelBase + '/resolve/' + $revision + '/' + $fileName) -OutFile $temporaryPath -TimeoutSec 300
                if (-not (Test-ModelFile $temporaryPath $entry)) { throw ('Model file integrity mismatch: ' + $fileName) }
                Move-Item -LiteralPath $temporaryPath -Destination $filePath -Force
                break
            } catch {
                if ($attempt -eq 3) { throw }
                Start-Sleep -Seconds 2
            }
        }
    } finally {
        if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath }
    }
}
Write-Output ('Model directory: ' + $cachePath)
