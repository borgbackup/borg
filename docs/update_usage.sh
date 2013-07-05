#!/usr/bin/bash
echo -n > usage.rst 
for cmd in init create extract delete prune verify change-passphrase; do
  LINE=`echo -n darc $cmd | tr 'a-z ' '~'`
  echo -e ".. _usage_darc_$cmd:\n\ndarc $cmd\n$LINE\n::\n" >> usage.rst
  darc $cmd -h >> usage.rst
done
