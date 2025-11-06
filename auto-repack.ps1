param(
    [Parameter(Mandatory)][string]$ApkPath,
    [Parameter(Mandatory)][string]$KeystorePath,
    [Parameter(Mandatory)][string]$KeystorePass,
    [Parameter(Mandatory)][string]$KeyAlias,
    [string]$WorkDir = "C:\\CONTRA16\\workspace",
    [string]$OutDir = "C:\\CONTRA16\\output",
    [string]$AndroidSdkRoot = $env:ANDROID_SDK_ROOT
)

$ErrorActionPreference = "Stop"
Write-Host "=== CONTRA16 AUTO REPACK ==="

if (-not (Test-Path $ApkPath)) { throw "APK not found: $ApkPath" }
if (-not (Test-Path $KeystorePath)) { throw "Keystore not found: $KeystorePath" }
if (-not $AndroidSdkRoot) { $AndroidSdkRoot = "C:\\Android\\Sdk" }

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Apktool = "C:\\CONTRA16\\apktool.bat"
$Apksigner = "$AndroidSdkRoot\\build-tools\\34.0.0\\apksigner.bat"

if (-not (Test-Path $Apktool)) { throw "apktool not found at $Apktool" }
if (-not (Test-Path $Apksigner)) { throw "apksigner not found. install build-tools." }

$DecodedDir = Join-Path $WorkDir "decoded"
$DistDir = Join-Path $WorkDir "dist"
$RebuiltApk = Join-Path $DistDir "rebuild-unsigned.apk"
$AlignedApk = Join-Path $DistDir "rebuild-aligned.apk"
$SignedApk = Join-Path $OutDir "contratool.apk"

Remove-Item $DecodedDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $DistDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[1/4] Decoding..."
& $Apktool d $ApkPath -o $DecodedDir -f

if (Test-Path "C:\CONTRA16\overrides") {
    Write-Host "Applying overrides..."
    Copy-Item -Path "C:\CONTRA16\overrides\*" -Destination $DecodedDir -Recurse -Force
}

Write-Host "[2/4] Rebuilding..."
& $Apktool b $DecodedDir -o $RebuiltApk

$Zipalign = "$AndroidSdkRoot\\build-tools\\34.0.0\\zipalign.exe"
if (Test-Path $Zipalign) {
    Write-Host "[3/4] Zipalign..."
    & $Zipalign -f 4 $RebuiltApk $AlignedApk
} else {
    Write-Host "zipalign missing, skipping."
    $AlignedApk = $RebuiltApk
}

Write-Host "[4/4] Signing..."
& $Apksigner sign `
    --ks $KeystorePath `
    --ks-key-alias $KeyAlias `
    --ks-pass pass:$KeystorePass `
    --key-pass pass:$KeystorePass `
    --out $SignedApk `
    $AlignedApk

Write-Host "=== DONE ==="
Write-Host "Signed APK: $SignedApk"
