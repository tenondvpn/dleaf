param(
    [ValidateSet("debug", "release")]
    [string]$Mode = "debug",
    [string]$OutDir = "$PSScriptRoot\..\..\Fluters\android\app\src\main\jniLibs"
)

$ErrorActionPreference = "Stop"

if (-not $Env:NDK_HOME) {
    throw "NDK_HOME is not set"
}

$repoRoot = Resolve-Path "$PSScriptRoot\.."
$ndkLlvmRoot = Join-Path $Env:NDK_HOME "toolchains\llvm\prebuilt\windows-x86_64"
$ndkBinRoot = Join-Path $ndkLlvmRoot "bin"
$api = "26"

if (-not $Env:LIBCLANG_PATH) {
    $libclangPath = Join-Path $ndkBinRoot "libclang.dll"
    if (Test-Path $libclangPath) {
        [Environment]::SetEnvironmentVariable("LIBCLANG_PATH", $ndkBinRoot, "Process")
    }
}

function Build-Target($target, $jniDir, $envPrefix, $clangTarget = $target) {
    $linker = Join-Path $ndkBinRoot "$clangTarget$api-clang.cmd"
    $ar = Join-Path $ndkBinRoot "llvm-ar.exe"

    if (-not (Test-Path $linker)) {
        throw "Android linker not found: $linker"
    }
    if (-not (Test-Path $ar)) {
        throw "Android archiver not found: $ar"
    }

    [Environment]::SetEnvironmentVariable("CC_$envPrefix", $linker, "Process")
    [Environment]::SetEnvironmentVariable("AR_$envPrefix", $ar, "Process")
    [Environment]::SetEnvironmentVariable("CARGO_TARGET_$($envPrefix.ToUpper())_LINKER", $linker, "Process")
    [Environment]::SetEnvironmentVariable("CARGO_TARGET_$($envPrefix.ToUpper())_AR", $ar, "Process")

    $targetOutDir = Join-Path $OutDir $jniDir
    New-Item $targetOutDir -ItemType Directory -Force | Out-Null

    $args = @("build", "--manifest-path", "$repoRoot\Cargo.toml", "-p", "leaf-android", "--target", $target, "--no-default-features", "--features", "default-ring")
    if ($Mode -eq "release") {
        $args += "--release"
    }
    cargo @args
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed for $target"
    }

    Copy-Item -Force "$repoRoot\target\$target\$Mode\libleafandroid.so" $targetOutDir
}

Build-Target "x86_64-linux-android" "x86_64" "x86_64_linux_android"
Build-Target "aarch64-linux-android" "arm64-v8a" "aarch64_linux_android"
Build-Target "i686-linux-android" "x86" "i686_linux_android"
Build-Target "armv7-linux-androideabi" "armeabi-v7a" "armv7_linux_androideabi" "armv7a-linux-androideabi"
