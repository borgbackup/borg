#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == "Darwin" ]]; then
    eval "$(pyenv init -)"
    # set our flags to use homebrew openssl
    export ARCHFLAGS="-arch x86_64"
    export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"
fi

# do not use fakeroot, but run as root on travis.
# avoids the dreaded EISDIR sporadic failures. see #2482.
sudo -E bash -c "source ~/.venv/bin/activate ; tox -e $TOXENV -r"
