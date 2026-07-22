# The borg 1.4 demo screencast, see README.rst.
#
# Everything below is "typed" into a shell by expect, so what you see in the
# screencast is what really happened - if borg changes, just record it again.

# Configuration for send -h
# Tries to emulate a human typing
# Tweak this if typing is too fast or too slow
set send_human {.07 .13 1 .02 .28}

set passphrase "correct horse battery staple"

# Colors for the lines we type. The output of the commands is not touched, it
# looks exactly like it looks in your terminal.
set color(reset) "\033\[0m"
set color(prompt) "\033\[1;36m"
set color(comment) "\033\[0;32m"
set color(command) "\033\[1;33m"
set color(option) "\033\[0;35m"

# Type a line like a human would, with a bit of syntax highlighting:
# comments in one color, the command in another one, its options in a third.
proc type_line {line} {
	global color
	if {[string index $line 0] eq "#"} {
		send_user -- $color(comment)
		send_user -h -- $line
		send_user -- $color(reset)\n
		return
	}
	set tokens [split $line " "]
	for {set i 0} {$i < [llength $tokens]} {incr i} {
		set token [lindex $tokens $i]
		if {$i > 0} {
			send_user -h " "
		}
		# "borg create" and friends: the subcommand belongs to the command
		if {$i == 0 || ($i == 1 && [lindex $tokens 0] eq "borg" && ![string match "-*" $token])} {
			send_user -- $color(command)
		} elseif {[string match "-*" $token]} {
			send_user -- $color(option)
		}
		send_user -h -- $token
		send_user -- $color(reset)
	}
	send_user \n
}

set script {
# Hi! This is a quick tour of BorgBackup 1.4 - deduplicating, compressing and encrypting backups.
# Note: made with __BORG_VERSION__, other versions may behave differently.

# This is the data we want to back up - some notes, logs and a project directory:
du -sh ~/Documents
ls ~/Documents

# Backups are stored in a "repository". Let's tell borg where ours is,
# so we do not have to repeat it in every command:
export BORG_REPO=/media/backup/borgdemo
# It could also live on another machine, e.g. ssh://user@server/./backup.

# Creating the repository - encrypted and authenticated, with the key stored in the repo itself:
borg init --encryption=repokey
# The key is protected by the passphrase we just typed - do not lose either of them!

# Typing that passphrase for every command would be boring here, so:
export BORG_PASSPHRASE='correct horse battery staple'
# For real backups, better use BORG_PASSCOMMAND and your password manager.

# Now our first backup. Every archive needs its own name, so we number them:
borg create --progress ::docs-1 ./Documents

# That was half a GB of files - but how much of it ended up in the repository?
du -sh /media/backup/borgdemo
# Quite a bit less - borg compressed it on the way in (lz4 by default, zstd packs more).

# Let's add a file...
echo "a new file" > ~/Documents/notes/newfile.txt

# ...and back up again:
borg create ::docs-2 ./Documents

# Much faster. And the repository did not really grow, either:
du -sh /media/backup/borgdemo
# Borg only stored what really changed - the rest was deduplicated.

# What if we move a big directory somewhere else?
mv ~/Documents/projects ~/Documents/projects-archived

borg create ::docs-3 ./Documents
du -sh /media/backup/borgdemo
# Also almost free: borg deduplicates by content, it does not care about the path.

# So, what do we have in the repository now?
borg list

# And what is inside such an archive?
borg list ::docs-3 | head -5

# What changed between our first two backups?
borg diff ::docs-1 docs-2

# Restoring a single file - extraction is relative to the current directory:
mkdir ~/restore
cd ~/restore
borg extract --noxattrs ::docs-2 Documents/notes/newfile.txt
cat Documents/notes/newfile.txt
cd ~

# You can also just browse your backups like a filesystem:
mkdir /tmp/mnt
borg mount :: /tmp/mnt
ls /tmp/mnt
ls /tmp/mnt/docs-3/Documents
borg umount /tmp/mnt

# Keeping only some archives is what "borg prune" is for (--dry-run shows what it would do):
borg prune --list --dry-run --keep-daily 7 --keep-weekly 4

# Single archives you do not need any more can also be deleted directly:
borg delete ::docs-1
borg list

# Space is only freed when you ask for it:
borg compact -v

# And of course you can verify that everything in the repository is still fine:
borg check -v

# That's it! Have a look at https://www.borgbackup.org/ for much more.
}

set script [string trim $script]
set script [string map [list __BORG_VERSION__ [exec borg --version]] $script]
set script [split $script \n]

# Always type an empty line before starting a new comment, so the screencast
# does not look like a wall of text.
set spaced {}
set previous ""
foreach line $script {
	if {[string index $line 0] eq "#" && $previous ne "" && [string index $previous 0] ne "#"} {
		lappend spaced ""
	}
	lappend spaced $line
	set previous $line
}
set script $spaced

# We echo the commands ourselves (with human-like typing), so switch off the
# echo of the terminal and use a minimal prompt.
set ::env(PS1) "$color(prompt)$ $color(reset)"
set stty_init -echo
set timeout -1

spawn -noecho /bin/sh
expect "$ "

foreach line $script {
	type_line $line
	send $line\n
	expect {
		"Enter new passphrase: " {
			send -h "$passphrase\n"
			exp_continue
		}
		"Enter same passphrase again: " {
			send -h "$passphrase\n"
			exp_continue
		}
		-re "Enter passphrase for key .*: " {
			send -h "$passphrase\n"
			exp_continue
		}
		-ex {Do you want your passphrase to be displayed for verification? [yN]: } {
			send \n
			exp_continue
		}
		"$ "
	}
}
