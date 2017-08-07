#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
    if [[ "${OPENSSL}" != "0.9.8" ]]; then
        brew outdated openssl || brew upgrade openssl
    fi

    if which pyenv > /dev/null; then
        eval "$(pyenv init -)"
    fi

    brew install lz4
    brew install xz  # required for python lzma module
    brew outdated pyenv || brew upgrade pyenv
    brew install pkg-config
    brew install Caskroom/cask/osxfuse

    case "${TOXENV}" in
        py35)
            pyenv install 3.5.2
            pyenv global 3.5.2
            ;;
        py36)
            pyenv install 3.6.0
            pyenv global 3.6.0
            ;;
    esac
    pyenv rehash
    python -m pip install --user virtualenv
else
    pip install virtualenv
    sudo apt-get update
    sudo apt-get install -y fakeroot
    sudo apt-get install -y liblz4-dev
    sudo apt-get install -y libacl1-dev
    sudo apt-get install -y libfuse-dev fuse pkg-config  # optional, for FUSE support
fi

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
pip install -r requirements.d/development.txt
pip install codecov
python setup.py --version
pip install -e .[fuse]
