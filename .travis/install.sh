#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
    export HOMEBREW_NO_AUTO_UPDATE=1
    export HOMEBREW_LOGS=~/brew-logs
    export HOMEBREW_TEMP=~/brew-temp
    mkdir $HOMEBREW_LOGS
    mkdir $HOMEBREW_TEMP
    brew update > /dev/null
    brew cleanup > /dev/null  # do this here, so it won't automatically trigger in the middle of other stuff
    brew outdated pkg-config || brew upgrade pkg-config
    # do NOT update openssl 1.0.x, brew will also update a lot of dependent pkgs (and their dependencies) then!
    #brew outdated openssl || brew upgrade openssl
    export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"
    brew install readline
    export PKG_CONFIG_PATH="/usr/local/opt/readline/lib/pkgconfig:$PKG_CONFIG_PATH"
    brew install zstd
    brew install lz4
    brew install xz  # required for python lzma module
    brew install Caskroom/cask/osxfuse

    brew outdated pyenv || brew upgrade pyenv
    if which pyenv > /dev/null; then
        eval "$(pyenv init -)"
    fi

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
    sudo apt-get install -y pkg-config fakeroot
    #sudo apt-get install -y liblz4-dev  # too old on trusty and xenial
    #sudo apt-get install -y libzstd-dev  # too old on trusty and xenial
    sudo apt-get install -y libacl1-dev
    sudo apt-get install -y libfuse-dev fuse  # optional, for FUSE support
fi

python -m virtualenv ~/.venv
source ~/.venv/bin/activate
pip install -r requirements.d/development.txt
pip install codecov
python setup.py --version
pip install -e .[fuse]
