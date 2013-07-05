#!/usr/bin/bash
echo -n > usage.rst 
for cmd in init create extract delete prune verify change-passphrase; do
  echo -e ".. _usage_darc_$cmd:\n\ndarc $cmd\n~~~~~~\n::\n" >> usage.rst
  darc $cmd -h >> usage.rst
done
