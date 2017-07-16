# This asciinema will show you the installation of borg as a standalone binary. Usually you only need this if you want to have an up-to-date version of borg or no package is available for your distro/OS.

# First, we need to download the version, we'd like to install…
wget -q --show-progress https://github.com/borgbackup/borg/releases/download/1.1.0b6/borg-linux64
# and do not forget the GPG signature…!
wget -q --show-progress https://github.com/borgbackup/borg/releases/download/1.1.0b6/borg-linux64.asc

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
