#!/bin/bash

set -e
set -x

# Travis clones with depth=50 which might be too shallow for git describe, see https://github.com/pypa/setuptools_scm/issues/93
git fetch --unshallow --tags

if [ "${TRAVIS_OS_NAME}" = "osx" ]
then

    # Update brew itself
    export HOMEBREW_NO_AUTO_UPDATE=1  # Auto-updating everything would take too much time
    brew update
    brew cleanup  # Preempt possible scheduled clean-up so it doesn't clutter the log later

    # Install and/or upgrade dependencies
    #brew install zstd || brew upgrade zstd  # Installation takes very long due to CMake dependency and isn't necessary for the tests as borg comes bundled with zstd anyway
    brew install lz4 || brew upgrade lz4
    brew install xz || brew upgrade xz  # Required for Python lzma module
    brew install Caskroom/cask/osxfuse || brew upgrade Caskroom/cask/osxfuse  # Required for Python llfuse module
    brew install pyenv || brew upgrade pyenv

    # Configure pkg-config to use OpenSSL 1.1 from Homebrew
    export PKG_CONFIG_PATH="/usr/local/opt/openssl@1.1/lib/pkgconfig:${PKG_CONFIG_PATH}"

    # Configure pyenv with Python version according to TOXENV
    eval "$(pyenv init -)"
    if [ "${TOXENV}" = "py35" ]
    then
        pyenv install 3.5.3  # Minimum version for OpenSSL 1.1.x
        pyenv global 3.5.3
    elif [ "${TOXENV}" = "py37" ]
    then
        pyenv install 3.7.0
        pyenv global 3.7.0
    else
        printf '%s\n' "Unexpected value for TOXENV environment variable"
        exit 1
    fi
    pyenv rehash

elif [ "${TRAVIS_OS_NAME}" = "linux" ]
then

    # Install dependencies
    sudo apt-get update
    sudo apt-get install -y pkg-config fakeroot
    #sudo apt-get install -y liblz4-dev  # Too old on trusty and xenial, but might be useful in future versions
    #sudo apt-get install -y libzstd-dev  # Too old on trusty and xenial, but might be useful in future versions
    sudo apt-get install -y libacl1-dev
    sudo apt-get install -y libfuse-dev fuse  # Required for Python llfuse module

else

    printf '%s\n' "Unexpected value for TRAVIS_OS_NAME environment variable"
    exit 1

fi

# Setup and activate virtual environment
python -m pip install virtualenv
python -m virtualenv ~/.venv
source ~/.venv/bin/activate

# Recent versions of OS X don't allow kernel extensions which makes the osxfuse tests fail; those versions are marked with SKIPFUSE=true in .travis.yml
if [ "${SKIPFUSE}" = "true" ]
then
    truncate -s 0 requirements.d/fuse.txt
fi

# Install requirements
pip install -r requirements.d/development.txt
pip install codecov
python setup.py --version
pip install -e .[fuse]
