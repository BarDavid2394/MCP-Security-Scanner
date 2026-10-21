$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$evaluation = Join-Path $root "evaluation"
$manifest = Get-Content (Join-Path $evaluation "corpus-manifest.json") -Raw | ConvertFrom-Json
$corpus = Join-Path $evaluation "corpus"
New-Item -ItemType Directory -Force -Path $corpus | Out-Null

function Invoke-Git {
    & git @args
    if ($LASTEXITCODE -ne 0) {
        throw "git command failed with exit code $LASTEXITCODE`: git $args"
    }
}

foreach ($repo in $manifest.repositories) {
    $destination = Join-Path $corpus $repo.id
    if (-not (Test-Path (Join-Path $destination ".git"))) {
        Invoke-Git clone --filter=blob:none --no-checkout $repo.url $destination
    }
    Invoke-Git -C $destination sparse-checkout init --cone
    Invoke-Git -C $destination sparse-checkout set -- $repo.sparse_paths
    Invoke-Git -C $destination fetch --depth 1 origin $repo.commit
    Invoke-Git -C $destination checkout --detach $repo.commit
    $actual = (& git -C $destination rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Could not resolve HEAD for $($repo.id)" }
    if ($actual -ne $repo.commit) {
        throw "Commit mismatch for $($repo.id): expected $($repo.commit), got $actual"
    }
    Write-Host "$($repo.id) $actual"
}
