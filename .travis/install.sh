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

    case "${TOXENV}" in
        py32)
            pyenv install 3.2.6
            pyenv global 3.2.6
            ;;
        py33)
            pyenv install 3.3.6
            pyenv global 3.3.6
            ;;
        py34)
            pyenv install 3.4.3
            pyenv global 3.4.3
            ;;
    esac
    pyenv rehash
    python -m pip install --user virtualenv
else
    pip install virtualenv
    sudo add-apt-repository -y ppa:gezakovacs/lz4
    sudo apt-get update
    sudo apt-get install -y liblz4-dev
    sudo apt-get install -y libacl1-dev
fi

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
pip install -r requirements.d/development.txt
pip install codecov
pip install -e .
