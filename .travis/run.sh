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
    # no fakeroot on OS X
    sudo tox -e $TOXENV -r
else
    fakeroot -f scripts/faked-debug.sh -u tox -r
fi
