#!/bin/bash

set -e
set -x

NO_COVERAGE_TOXENVS=(pep8)
if ! [[ "${NO_COVERAGE_TOXENVS[*]}" =~ "${TOXENV}" ]]; then
    source ~/.venv/bin/activate
    # on osx, tests run as root, need access to .coverage
    sudo chmod 666 .coverage
    codecov -e TRAVIS_OS_NAME TOXENV
fi
