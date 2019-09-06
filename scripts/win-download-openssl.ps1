# Download and extract the prebuilt openssl libraries provided by the python developers.
# The file is extracted to the .\external directory.

$url = "https://github.com/python/cpython-bin-deps/archive/openssl-bin-1.1.1c.zip"
$dest = "external"

$ErrorActionPreference = "Stop"

Write-Output "Downloading OpenSSL from cpython-bin-deps repository ..." 
Invoke-WebRequest $url -OutFile openssl.zip

Write-Output "Extracting OpenSSL"
Expand-Archive -Path openssl.zip -DestinationPath $dest -Force

Remove-Item -Path openssl.zip
