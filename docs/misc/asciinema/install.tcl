# Configuration for send -h
# Tries to emulate a human typing
# Tweak this if typing is too fast or too slow
set send_human {.05 .1 1 .01 .2}

set script [string trim {
# This asciinema will show you the installation of borg as a standalone binary. Usually you only need this if you want to have an up-to-date version of borg or no package is available for your distro/OS.

# First, we need to download the version, we'd like to install…
wget -q --show-progress https://github.com/borgbackup/borg/releases/download/1.2.1/borg-linux64
# and do not forget the GPG signature…!
wget -q --show-progress https://github.com/borgbackup/borg/releases/download/1.2.1/borg-linux64.asc

# In this case, we have already imported the public key of a borg developer. So we only need to verify it:
gpg --verify borg-linux64.asc
# Okay, the binary is valid!

# Now install it:
sudo cp borg-linux64 /usr/local/bin/borg
sudo chown root:root /usr/local/bin/borg
# and make it executable…
sudo chmod 755 /usr/local/bin/borg

# Now check it: (possibly needs a terminal restart)
borg -V

# That's it! Check out the other screencasts to see how to actually use borgbackup.
}]

# wget may be slow
set timeout -1

foreach line [split $script \n] {
	send_user "$ "
	send_user -h $line\n
	spawn -noecho /bin/sh -c $line
	expect eof
}
