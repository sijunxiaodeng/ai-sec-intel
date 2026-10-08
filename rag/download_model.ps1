# Optional Windows download path when the Python TLS client cannot reach Hugging Face.
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$cachePath = Join-Path $repoRoot 'data/models/bge-small-zh-v1.5-local'
$revision = '46fbe35fd4374a00fee7de77dfddaeb6dd6a2c59'
$modelBase = 'https://huggingface.co/Qdrant/bge-small-zh-v1.5'
$metadataUrl = 'https://huggingface.co/api/models/Qdrant/bge-small-zh-v1.5/revision/' + $revision + '?blobs=true'
$metadata = Invoke-RestMethod -Uri $metadataUrl -TimeoutSec 30
$files = @('config.json', 'model_optimized.onnx', 'special_tokens_map.json', 'tokenizer.json', 'tokenizer_config.json', 'vocab.txt')
New-Item -ItemType Directory -Path $cachePath -Force | Out-Null
foreach ($fileName in $files) {
    $filePath = Join-Path $cachePath $fileName
    $entry = $metadata.siblings | Where-Object { $_.rfilename -eq $fileName }
    if ((Test-Path -LiteralPath $filePath) -and $entry.lfs.sha256) {
        $existing = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($existing -eq $entry.lfs.sha256) { Write-Output ('Cached ' + $fileName); continue }
    }
    Write-Output ('Downloading ' + $fileName)
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Invoke-WebRequest -Uri ($modelBase + '/resolve/' + $revision + '/' + $fileName) -OutFile $filePath -TimeoutSec 300
            break
        } catch {
            if ($attempt -eq 3) { throw }
            Start-Sleep -Seconds 2
        }
    }
    if ($entry.lfs.sha256) {
        $actual = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $entry.lfs.sha256) { throw ('SHA256 mismatch: ' + $fileName) }
    }
}
Write-Output ('Model directory: ' + $cachePath)
