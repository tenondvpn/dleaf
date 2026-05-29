param(
    [ValidateSet("debug", "release")]
    [string]$Mode = "release",
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$OutDir = "$PSScriptRoot\..\..\Fluters\windows\runner\libs\x64",
    [string]$Toolchain = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path "$PSScriptRoot\.."
$outDirPath = New-Item $OutDir -ItemType Directory -Force

$cargoArgs = @(
    "build",
    "--manifest-path", "$repoRoot\Cargo.toml",
    "-p", "leaf-ffi",
    "--target", $Target,
    "--no-default-features",
    "--features", "default-ring"
)
$cargoCommand = "cargo"
if (-not [string]::IsNullOrWhiteSpace($Toolchain)) {
    $cargoCommand = "cargo"
    $cargoArgs = @("+$Toolchain") + $cargoArgs
}
if ($Mode -eq "release") {
    $cargoArgs += "--release"
}

& $cargoCommand @cargoArgs
if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed with exit code $LASTEXITCODE"
}

$artifactDir = Join-Path $repoRoot "target\$Target\$Mode"
Copy-Item -Force (Join-Path $artifactDir "leaf.lib") $outDirPath.FullName

$lwipLib = Get-ChildItem -Path (Join-Path $repoRoot "target\$Target\$Mode\build") -Recurse -Filter "lwip.lib" | Select-Object -First 1
if ($lwipLib) {
    Copy-Item -Force $lwipLib.FullName $outDirPath.FullName
}

$headerPath = Join-Path $repoRoot "target\$Target\$Mode\leaf.h"
& cbindgen --config (Join-Path $PSScriptRoot "cbindgen.toml") (Join-Path $PSScriptRoot "src\lib.rs") | Set-Content -Encoding ascii $headerPath
if ($LASTEXITCODE -ne 0) {
    throw "cbindgen failed with exit code $LASTEXITCODE"
}
Copy-Item -Force $headerPath (Resolve-Path "$repoRoot\..\Fluters\windows\runner\leaf.h")

Write-Host "Copied leaf.lib to $($outDirPath.FullName)"
if ($lwipLib) {
    Write-Host "Copied lwip.lib to $($outDirPath.FullName)"
}
Write-Host "Copied leaf.h to Fluters\windows\runner\leaf.h"
Write-Host "If Windows TUN is enabled, copy the matching wintun.dll to $($outDirPath.FullName) before running Fluters."
