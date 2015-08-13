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
    sudo apt-get install -y libacl1-dev
fi

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
pip install tox pytest pytest-cov codecov Cython
pip install -e .
