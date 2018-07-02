#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == "Darwin" ]]; then
    eval "$(pyenv init -)"
    if [[ "${OPENSSL}" != "0.9.8" ]]; then
        # set our flags to use homebrew openssl
        export ARCHFLAGS="-arch x86_64"
        export LDFLAGS="-L/usr/local/opt/openssl/lib"
        export CFLAGS="-I/usr/local/opt/openssl/include"
    fi
fi

source ~/.venv/bin/activate

RUST_LOG=warn test-wrapper/target/release/test-wrapper tox -r
