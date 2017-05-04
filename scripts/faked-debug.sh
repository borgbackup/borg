#!/bin/sh
if which faked; then
  faked --debug "$@"
else
  faked-sysv --debug "$@"
fi
