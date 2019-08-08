
REM Use the downloaded OpenSSL, for all other libraries the bundled version is used.
REM On Appveyor different OpenSSL versions are available, therefore the directory contains the version information.
set BORG_OPENSSL_PREFIX=C:\OpenSSL-v111-Win64
set BORG_USE_BUNDLED_B2=YES
set BORG_USE_BUNDLED_LZ4=YES
set BORG_USE_BUNDLED_ZSTD=YES
set BORG_USE_BUNDLED_XXHASH=YES

REM Somehow on my machine rc.exe was not found. Adding the Windows Kit to the path worked.
set PATH=%PATH%;C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x64

REM Run the build in the project directory.
SET WORKPATH=%~dp0\..
pushd %WORKPATH%

python setup.py clean
pip install -v -e .

popd
