#!/usr/bin/env expect

if {[file isdirectory /media/backup/borgdemo] == 0} {
  send_user "Please, run basic-prepare.sh first\n"
  exit 1
}

# Configuration for send -h
# Tries to emulate a human typing
# Tweak this if typing is too fast or too slow
set send_human {.05 .1 1 .01 .2}

# The screencast uses relative paths "Wallpaper"
# We should not mess with the contents of whatever cwd happened to be
cd [exec mktemp -d]
mkdir Wallpaper

if {0} {
  spawn borg init --encryption=repokey /media/backup/borgdemo
  expect "Enter new passphrase: "
  send -h "correct horse battery staple\n"
  expect "Enter same passphrase again: "
  send -h "correct horse battery staple\n"
  expect -ex {Do you want your passphrase to be displayed for verification? [yN]: }
  send \n
  expect eof
}
