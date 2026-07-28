param(
    [string] $Version = "0.1.0"
)

$ErrorActionPreference = 'Stop'

$pluginRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$wordpressRoot = Resolve-Path (Join-Path $pluginRoot '..')
$dist = Join-Path $wordpressRoot 'dist'
$staging = Join-Path $dist 'lykanshield'
$zip = Join-Path $dist ("lykanshield-$Version.zip")
$checksum = "$zip.sha256"

if (Test-Path $staging) {
    Remove-Item -LiteralPath $staging -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $dist | Out-Null
New-Item -ItemType Directory -Force -Path $staging | Out-Null

$excluded = @(
    '\tests\',
    '\tools\',
    '\phpcs.xml.dist'
)

Get-ChildItem -LiteralPath $pluginRoot -Recurse -Force | ForEach-Object {
    $relative = $_.FullName.Substring($pluginRoot.Path.Length)

    foreach ($pattern in $excluded) {
        if ($relative -like "*$pattern*") {
            return
        }
    }

    $target = Join-Path $staging $relative.TrimStart('\')

    if ($_.PSIsContainer) {
        New-Item -ItemType Directory -Force -Path $target | Out-Null
        return
    }

    New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent) | Out-Null
    Copy-Item -LiteralPath $_.FullName -Destination $target -Force
}

if (Test-Path $zip) {
    Remove-Item -LiteralPath $zip -Force
}

Compress-Archive -LiteralPath $staging -DestinationPath $zip -CompressionLevel Optimal
$hash = Get-FileHash -LiteralPath $zip -Algorithm SHA256
Set-Content -LiteralPath $checksum -Value ($hash.Hash.ToLowerInvariant() + "  " + (Split-Path $zip -Leaf))

Write-Output $zip
Write-Output $checksum
