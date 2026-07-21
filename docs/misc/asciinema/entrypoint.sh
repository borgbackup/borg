#!/bin/sh
# Record the borg 1.4 demo screencast. Runs inside the container, see README.rst.
set -eu

CAST=borg14-demo.cast  # this is also the name record.exp gives to asciinema

# Always start from the same state, so that re-recording is reproducible.
rm -rf /media/backup/borgdemo /home/user/Documents /home/user/restore \
       /home/user/.config/borg /home/user/.cache/borg
mkdir -p /media/backup/borgdemo
cp -a /opt/demo-data /home/user/Documents
chown -R user:user /home/user /media/backup

su - user -c "expect -f /demo/record.exp"

# The recording runs as user "user", which usually can not write to the bind
# mounted output directory, so copy the result over as root.
cp "/tmp/$CAST" "/out/$CAST"
echo "recorded: /out/$CAST"
