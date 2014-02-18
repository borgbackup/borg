#!/usr/bin/bash
if [ ! -d usage ]; then
  mkdir usage
fi
for cmd in change-passphrase check create delete extract info init list mount prune; do
  FILENAME="usage/$cmd.rst.inc"
  LINE=`echo -n attic $cmd | tr 'a-z- ' '-'`
  echo -e ".. _attic_$cmd:\n" > $FILENAME
  echo -e "attic $cmd\n$LINE\n::\n\n" >> $FILENAME
  attic $cmd -h | sed -e 's/^/    /' >> $FILENAME
  echo -e "\nDescription\n~~~~~~~~~~~\n\n" >> $FILENAME
done
