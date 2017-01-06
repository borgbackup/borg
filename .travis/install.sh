#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
    brew update || brew update

    if [[ "${OPENSSL}" != "0.9.8" ]]; then
        brew outdated openssl || brew upgrade openssl
    fi

    if which pyenv > /dev/null; then
        eval "$(pyenv init -)"
    fi

    brew install lz4
    brew outdated pyenv || brew upgrade pyenv
    brew install pkg-config
    brew install Caskroom/cask/osxfuse

    case "${TOXENV}" in
        py34)
            pyenv install 3.4.3
            pyenv global 3.4.3
            ;;
        py35)
            pyenv install 3.5.1
            pyenv global 3.5.1
            ;;
    esac
    pyenv rehash
    python -m pip install --user 'virtualenv<14.0'
else
    pip install 'virtualenv<14.0'
    sudo apt-get update
    sudo apt-get install -y liblz4-dev
    sudo apt-get install -y libacl1-dev
    sudo apt-get install -y libfuse-dev fuse pkg-config  # optional, for FUSE support
fi

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
pip install -r requirements.d/development.txt
pip install codecov
pip install -e .[fuse]
