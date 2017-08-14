# For the pro users, here are some advanced features of borg, so you can impress your friends. ;)
# Note: This screencast was made with borg version 1.1.0 – older or newer borg versions may behave differently.

# First of all, we can use several environment variables for borg.
# E.g. we do not want to type in our repo path and password again and again…
export BORG_REPO='/media/backup/borgdemo'
export BORG_PASSPHRASE='1234'
# Problem solved, borg will use this automatically… :)
# We'll use this right away…

## ADVANCED CREATION ##

# We can also use some placeholders in our archive name…
borg create --stats --progress --compression lz4 ::{user}-{now} Wallpaper
# Notice the backup name.

# And we can put completely different data, with different backup settings, in our backup. It will be deduplicated, anyway:
borg create --stats --progress --compression zlib,6 --exclude ~/Downloads/big ::{user}-{now} ~/Downloads

# Or let's backup a device via STDIN.
sudo dd if=/dev/loop0 bs=10M | borg create --progress --stats ::specialbackup -

# Let's continue with some simple things:
## USEFUL COMMANDS ##
# You can show some information about an archive. You can even do it without needing to specify the archive name:
borg info :: --last 1

# So let's rename our last archive:
borg rename ::specialbackup backup-block-device
<up>
borg info :: --last 1

# A very important step if you choose keyfile mode (where the keyfile is only saved locally) is to export your keyfile and possibly print it, etc.
borg key export :: --qr-code file.html # this creates a nice HTML, but when you want something simpler…
< remove comment >
< let there: borg check > --paper # this is a "manual input"-only backup (but it is also included in the --qr-code option)

## MAINTENANCE ##
# Sometimes backups get broken or we want a regular "checkup" that everything is okay…
borg check -v ::

# Next problem: Usually you do not have infinite disk space. So you may need to prune your archive…
# You can tune this in every detail. See the docs for details. Here only a simple example:
borg prune --list --keep-last 1 --dry-run
# When actually executing it in a script, you have to use it without the --dry-run option, of course.

## RESTORE ##

# When you want to see the diff between two archives use this command.
# E.g. what happened between the first two backups?
borg diff ::backup1 backup2
# Ah, we added a file, right…

# There are also other ways to extract the data.
# E.g. as a tar archive.
borg export-tar --progress ::backup2 backup.tar.gz
ls -l

# You can mount an archive or even the whole repository:
mkdir /tmp/mount
borg mount :: /tmp/mount
ls -la /tmp/mount
borg umount /tmp/mount

# That's it, but of course there is more to explore, so have a look at the docs.
