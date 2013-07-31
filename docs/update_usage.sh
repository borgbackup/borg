#!/usr/bin/bash
if [ ! -d usage ]; then
  mkdir usage
fi
for cmd in change-passphrase create delete extract info init list mount prune verify; do
  FILENAME="usage/$cmd.rst.inc"
  echo -e "Synopsis\n~~~~~~~~\n::\n" > $FILENAME
  attic $cmd -h | sed -e 's/^/    /' >> $FILENAME
done
