# Configure the environment such that borg can be built and run.
# Note that building borg requires OpenSSL which is not available by default.
# Use the win-download-openssl.ps1 script to get correct OpenSSL version.

$opensslPath = Resolve-Path "$PSScriptRoot\..\external\cpython-bin-deps-openssl-bin-1.1.1c\$env:PROCESSOR_ARCHITECTURE"
if(!(Test-Path $opensslPath)) {
    Write-Host "OpenSSL not found! Please run win-download-openssl.ps1 and check if your platform is supported."
    exit
}

$env:BORG_OPENSSL_PREFIX = $opensslPath
$env:BORG_USE_BUNDLED_B2 = "YES"
$env:BORG_USE_BUNDLED_LZ4 = "YES"
$env:BORG_USE_BUNDLED_ZSTD = "YES"
$env:BORG_USE_BUNDLED_XXHASH = "YES"

Write-Host "Environment configured for borg. The following variables where set:"
Write-Host ( Get-ChildItem Env: | Where-Object { $_.Name.StartsWith("BORG_") } | Out-String )
