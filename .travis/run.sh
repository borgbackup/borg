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

if [[ "$(uname -s)" == "Darwin" ]]; then
    # currently test-wrapper doesn't work on OSX
    # this will be fixed if we can figure out how to intercept unlink
    sudo tox -r -e "$TOXENV"
else
    test-wrapper/target/release/test-wrapper tox -r
fi
