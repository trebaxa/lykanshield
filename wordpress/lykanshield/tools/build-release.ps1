param(
    [string] $Version = '0.1.0',
    [string] $OutputDir = (Join-Path $PSScriptRoot '..\dist')
)

$ErrorActionPreference = 'Stop'

$pluginRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$outputRoot = New-Item -ItemType Directory -Path $OutputDir -Force
$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('lykanshield-release-' + [System.Guid]::NewGuid().ToString('N'))
$stagePlugin = Join-Path $stageRoot 'lykanshield'

New-Item -ItemType Directory -Path $stagePlugin -Force | Out-Null

$excluded = @(
    '\.git($|\\)',
    '\\dist($|\\)',
    '\\tests($|\\)',
    '\\tools($|\\)',
    '\\vendor($|\\)',
    '\\node_modules($|\\)',
    '\\\.phpunit\.cache($|\\)'
)

Get-ChildItem -Path $pluginRoot -Recurse -Force | ForEach-Object {
    $relative = $_.FullName.Substring($pluginRoot.Path.Length).TrimStart('\')
    if ($relative -eq '') {
        return
    }

    foreach ($pattern in $excluded) {
        if ($_.FullName.Substring($pluginRoot.Path.Length) -match $pattern) {
            return
        }
    }

    $target = Join-Path $stagePlugin $relative
    if ($_.PSIsContainer) {
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        return
    }

    New-Item -ItemType Directory -Path (Split-Path $target -Parent) -Force | Out-Null
    Copy-Item -LiteralPath $_.FullName -Destination $target
}

$zipPath = Join-Path $outputRoot.FullName ('lykanshield-' + $Version + '.zip')
if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath
}

Compress-Archive -Path $stagePlugin -DestinationPath $zipPath -CompressionLevel Optimal
Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath | ForEach-Object {
    $_.Hash.ToLowerInvariant() + '  ' + (Split-Path $_.Path -Leaf)
} | Set-Content -Path ($zipPath + '.sha256') -Encoding ASCII

Remove-Item -LiteralPath $stageRoot -Recurse -Force

Write-Output $zipPath
