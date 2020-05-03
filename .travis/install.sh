#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
    # HOMEBREW_NO_AUTO_UPDATE=1
    export HOMEBREW_LOGS=~/brew-logs
    export HOMEBREW_TEMP=~/brew-temp
    mkdir $HOMEBREW_LOGS
    mkdir $HOMEBREW_TEMP

    # Brew removed openssl@1.0 end of 2019 https://brew.sh/2019/11/27/homebrew-2.2.0/
    # Use rbenv's formula fork https://github.com/rbenv/homebrew-tap/blob/master/Formula/openssl%401.0.rb
    brew install rbenv/tap/openssl@1.0

    if which pyenv > /dev/null; then
        eval "$(pyenv init -)"
    fi

    brew install lz4
    brew outdated pyenv || brew upgrade pyenv
    brew install pkg-config
    brew install Caskroom/cask/osxfuse

    case "${TOXENV}" in
        py34)
            PYTHON_BUILD_HOMEBREW_OPENSSL_FORMULA=openssl@1.0 pyenv install 3.4.5
            pyenv global 3.4.5
            ;;
        py35)
            PYTHON_BUILD_HOMEBREW_OPENSSL_FORMULA=openssl@1.0 pyenv install 3.5.2
            pyenv global 3.5.2
            ;;
        py36)
            pyenv install 3.6.0
            pyenv global 3.6.0
            ;;
    esac
    pyenv rehash
    python -m pip install --user 'virtualenv<14.0'
else
    pip install 'virtualenv<14.0'
    sudo apt-get update
    sudo apt-get install -y fakeroot
    sudo apt-get install -y liblz4-dev
    sudo apt-get install -y libacl1-dev
    sudo apt-get install -y libfuse-dev fuse pkg-config  # optional, for FUSE support
fi

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
pip install -r requirements.d/development.lock.txt
pip install codecov
python setup.py --version
pip install -e .[fuse]
