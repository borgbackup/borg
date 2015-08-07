#!/bin/bash

set -e
set -x

NO_COVERAGE_TOXENVS=(pep8)
if ! [[ "${NO_COVERAGE_TOXENVS[*]}" =~ "${TOXENV}" ]]; then
    source ~/.venv/bin/activate
    ln .tox/.coverage .coverage
    codecov -e TRAVIS_OS_NAME,TOXENV
fi
