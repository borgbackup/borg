#!/bin/sh
# For whatever reason, --debug fixes some EISDIR errors.
# See #2455 and #2048 for details.
if which faked; then
  faked --debug "$@"
else
  faked-sysv --debug "$@"
fi
