# Configuration for send -h
# Tries to emulate a human typing
# Tweak this if typing is too fast or too slow
set send_human {.05 .1 1 .01 .2}

set script {
# Here you'll see some basic commands to start working with borg.
# Note: This teaser screencast was made with __BORG_VERSION__ – older or newer borg versions may behave differently.
# But let's start.

# First of all, you can always get help:
borg help
# These are a lot of commands, so better we start with a few:
# Let's create a repo on an external drive…
borg init --encryption=repokey /media/backup/borgdemo
# This uses the repokey encryption. You may look at "borg help init" or the online doc at https://borgbackup.readthedocs.io/ for other modes.

# So now, let's create our first (compressed) backup.
borg create --stats --progress --compression lz4 /media/backup/borgdemo::backup1 Wallpaper

# That's nice, so far.
# So let's add a new file…
echo "new nice file" > Wallpaper/newfile.txt

borg create --stats --progress --compression lz4 /media/backup/borgdemo::backup2 Wallpaper

# Wow, this was a lot faster!
# Notice the "Deduplicated size" for "This archive"!
# Borg recognized that most files did not change and deduplicated them.

# But what happens, when we move a dir and create a new backup?
mv Wallpaper/bigcollection Wallpaper/bigcollection_NEW

borg create --stats --progress --compression lz4 /media/backup/borgdemo::backup3 Wallpaper

# Still quite fast…
# But when you look at the "deduplicated file size" again, you see that borg also recognized that only the dir and not the files changed in this backup.

# Now lets look into a repo.
borg list /media/backup/borgdemo

# You'll see a list of all backups.
# You can also use the same command to look into an archive. But we better filter the output here:
borg list /media/backup/borgdemo::backup3 | grep 'deer.jpg'

# Oh, we found our picture. Now extract it…
mv Wallpaper Wallpaper.orig
borg extract /media/backup/borgdemo::backup3 Wallpaper/deer.jpg


# And check that it's the same:
diff -s Wallpaper/deer.jpg Wallpaper.orig/deer.jpg

# And, of course, we can also create remote repos via ssh when borg is setup there. This command creates a new remote repo in a subdirectory called "demo":
borg init --encryption=repokey borgdemo@remoteserver.example:./demo

# Easy, isn't it? That's all you need to know for basic usage.
# If you want to see more, have a look at the screencast showing the "advanced usage".
# In any case, enjoy using borg!
}

set script [string trim $script]
set script [string map [list __BORG_VERSION__ [exec borg -V]] $script]
set script [split $script \n]

foreach line $script {
  send_user "$ "
  send_user -h $line\n
  spawn -noecho /bin/sh -c $line
  expect {
    "Enter new passphrase: " {
      send -h "correct horse battery staple\n"
      exp_continue
    }
    "Enter same passphrase again: " {
      send -h "correct horse battery staple\n"
      exp_continue
    }
    "Enter passphrase for key /media/backup/borgdemo: " {
      send -h "correct horse battery staple\n"
      exp_continue
    }
    -ex {Do you want your passphrase to be displayed for verification? [yN]: } {
      send \n
      exp_continue
    }
    eof
  }
}
