#!/bin/bash
if [ ! -d usage ]; then
  mkdir usage
fi
for cmd in change-passphrase check create delete extract info init list mount prune serve; do
  FILENAME="usage/$cmd.rst.inc"
  LINE=`echo -n borg $cmd | tr 'a-z- ' '-'`
  echo -e ".. _borg_$cmd:\n" > $FILENAME
  echo -e "borg $cmd\n$LINE\n::\n\n" >> $FILENAME
  borg help $cmd --usage-only | sed -e 's/^/    /' >> $FILENAME
  echo -e "\nDescription\n~~~~~~~~~~~\n" >> $FILENAME
  borg help $cmd --epilog-only >> $FILENAME
done
