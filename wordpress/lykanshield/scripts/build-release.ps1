param(
    [string] $Version = '0.1.0'
)

$ErrorActionPreference = 'Stop'

$PluginRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')
$DistRoot = Join-Path $PluginRoot 'dist'
$PackageRoot = Join-Path $DistRoot 'lykanshield'
$ZipPath = Join-Path $DistRoot ("lykanshield-{0}.zip" -f $Version)
$ChecksumPath = $ZipPath + '.sha256'

if (Test-Path -LiteralPath $PackageRoot) {
    Remove-Item -LiteralPath $PackageRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $PackageRoot -Force | Out-Null
New-Item -ItemType Directory -Path $DistRoot -Force | Out-Null

$ExcludedDirectories = @('.git', '.github', '.idea', '.vscode', 'dist', 'tests', 'scripts')
$ExcludedExtensions = @('.log', '.tmp', '.cache', '.pem', '.key')

Get-ChildItem -LiteralPath $PluginRoot -Recurse -File | ForEach-Object {
    $relative = $_.FullName.Substring($PluginRoot.Path.Length).TrimStart('\', '/')
    $parts = $relative -split '[\\/]'

    foreach ($directory in $ExcludedDirectories) {
        if ($parts -contains $directory) {
            return
        }
    }

    if ($_.Name -eq '.env' -or $_.Name.StartsWith('.env.')) {
        return
    }

    if ($ExcludedExtensions -contains $_.Extension.ToLowerInvariant()) {
        return
    }

    $target = Join-Path $PackageRoot $relative
    $targetDirectory = Split-Path -Parent $target
    New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
    Copy-Item -LiteralPath $_.FullName -Destination $target -Force
}

if (Test-Path -LiteralPath $ZipPath) {
    Remove-Item -LiteralPath $ZipPath -Force
}

Compress-Archive -LiteralPath $PackageRoot -DestinationPath $ZipPath -Force

$hash = Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256
Set-Content -LiteralPath $ChecksumPath -Value ($hash.Hash.ToLowerInvariant() + '  ' + (Split-Path -Leaf $ZipPath)) -Encoding ASCII

Write-Output ("Created {0}" -f $ZipPath)
Write-Output ("Created {0}" -f $ChecksumPath)
