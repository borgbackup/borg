## CLient side

The state of this document and the associated script is beta, please use with caution.

### QuickStart

Create and run the borg backup container.
In this quick start, the `/etc` and `/home` directories
from the host are bind mounted to the container as read only. These are
the directories which will be backed up. The backed up data will be stored
in the `borg-repo` Docker volume, and the data will be encrypted with a key 
protected with the `my-secret-pw` password. If the host is using SELinux, the
`--security-opt label:disable` flag must be used, because we don't want
to relabel the `/etc` and `/home` directories while we want the container
to have access to them. After the backup is done, data will be pruned
according to the default policy and checked for errors. Borg is running
in a verbose mode within the container, so the detailed output from backup
will be printed. 

```
docker run \
  -e BORG_REPO=/borg/repo \
  -e BORG_PASSPHRASE=my-secret-pw \
  -e EXCLUDE='*/.cache*;*.tmp;/borg/data/etc/shadow' \
  -e COMPRESSION=lz4 \
  -e PRUNE=1 \
  -v borg-cache:/root/.cache/borg \
  -v borg-repo:/borg/repo \
  -v /etc:/borg/data/etc:ro \
  -v /home:/borg/data/home:ro \
  --security-opt label:disable \
  --entrypoint=/usr/bin/borgbackup \
  --name borg-backup \
  borgbackup/borg
```

### More examples

Backup docker volumes to remote location (Borg must be running in server mode at that remote location):

```
docker run \
  -e BORG_REPO='user@hostname:/path/to/repo' \
  -e ARCHIVE=wordpress-{now:%Y-%m-%d} \
  -e BORG_PASSPHRASE=my-secret-pw \
  -e BACKUP_DIRS=/borg/data \
  -e COMPRESSION=lz4 \
  -e PRUNE=1 \
  -v borg-cache:/root/.cache/borg \
  -v mariadb-data:/borg/data/mariadb:ro \
  -v wordpress-data:/borg/data/wordpress:ro \
  --entrypoint=/usr/bin/borgbackup \
  --name borg-backup \
  borgbackup/borg
```

Using sshfs (in case when the Borg is not installed on the remote location):

```
docker run \
  -e SSHFS='user@hostname:/path/to/repo' \
  -e SSHFS_PASSWORD=my-ssh-password \
  -e BORG_PASSPHRASE=my-secret-pw \
  -e BACKUP_DIRS=/borg/data \
  -e COMPRESSION=lz4 \
  -e PRUNE=1 \
  -v borg-cache:/root/.cache/borg \
  -v mariadb-data:/borg/data/mariadb:ro \
  -v wordpress-data:/borg/data/wordpress:ro \
  --cap-add SYS_ADMIN --device /dev/fuse --security-opt label:disable \
  --entrypoint=/usr/bin/borgbackup \
  --name borg-backup \
  borgbackup/borg
```

Using sshfs with ssh key authentication:

```
docker run \
  -e SSHFS='user@hostname:/path/to/repo' \
  -e SSHFS_IDENTITY_FILE=/root/ssh-key/key \
  -e SSHFS_GEN_IDENTITY_FILE=1 \
  -e BORG_PASSPHRASE=my-secret-pw \
  -e BACKUP_DIRS=/borg/data \
  -e COMPRESSION=lz4 \
  -e PRUNE=1 \
  -v borg-cache:/root/.cache/borg \
  -v borg-ssh-key:/root/ssh-key \
  -v mariadb-data:/borg/data/mariadb:ro \
  -v wordpress-data:/borg/data/wordpress:ro \
  --cap-add SYS_ADMIN --device /dev/fuse --security-opt label:disable \
  --entrypoint=/usr/bin/borgbackup \
  --name borg-backup \
  borgbackup/borg
```

Restoring files from specific day to folder on host:

```
docker run \
  -e BORG_REPO='user@hostname:/path/to/repo' \
  -e ARCHIVE=wordpress-2016-05-25 \
  -e BORG_PASSPHRASE=my-secret-pw \
  -e EXTRACT_TO=/borg/restore \
  -e EXTRACT_WHAT=only/this/file \
  -v borg-cache:/root/.cache/borg \
  -v /opt/restore:/borg/restore \
  --security-opt label:disable \
  --entrypoint=/usr/bin/borgbackup \
  --name borg-backup \
  borgbackup/borg
```

Running custom borg command:

```
docker run \
  -e BORG_REPO='user@hostname:/path/to/repo' \
  -e BORG_PASSPHRASE=my-secret-pw \
  -e BORG_PARAMS='list ::2016-05-26' \
  -v borg-cache:/root/.cache/borg \
  --entrypoint=/usr/bin/borgbackup \
  --name borg-backup \
  borgbackup/borg
```

## Environment variables

This docker image accepts [environment variables from borg](https://borgbackup.readthedocs.io/en/stable/usage/general.html#environment-variables), and some more described here:

### Core variables

**ARCHIVE** - archive parameter for Borg repository. If empty, defaults to `"{hostname}_{now:%Y-%m-%d}"`. For more info see [Borg documentation](https://borgbackup.readthedocs.io/en/stable/usage.html)

**BACKUP_DIRS** - directories to back up

**EXCLUDE** - paths/patterns to exclude from backup. Paths must be separated by `;`. For example: `-e EXCLUDE='/my path/one;/path two;*.tmp'`

**BORG_PARAMS** - run custom borg command inside of the container. If this variable is set, default commands are not executed, only the one specified in *BORG_PARAMS*. For example `list` or `list ::2016-05-26`. In both examples, repo is not specified, because borg understands the `BORG_REPO` env var and uses it by default

**BORG_SKIP_CHECK** - set to `1` if you want to skip the `borg check` command at the end of the backup

**SSH_KEY** - set the ssh key when you start this image in server mode

### Compression

**COMPRESSION** - compression to use. Defaults to lz4. [More info](https://borgbackup.readthedocs.io/en/stable/usage.html#borg-create)

### Extracting (restoring) files

**EXTRACT_TO** - directory where to extract (restore) borg archive. If this variable is set, default commands are not executed, only the extraction is done. Repo and archive are specified with *BORG_REPO* and *ARCHIVE* variables. [More info](https://borgbackup.readthedocs.io/en/stable/usage.html#borg-extract)

**EXTRACT_WHAT** - subset of files and directories which should be extracted

### Pruning

**PRUNE** - if set, prune the repository after backup. Empty by default. [More info](https://borgbackup.readthedocs.io/en/stable/usage.html#borg-prune)

**PRUNE_PREFIX** - filter data to prune by prefix of the archive. Empty by default - prune all data

**KEEP_DAILY** - keep specified number of daily backups. Defaults to 7

**KEEP_WEEKLY** - keep specified number of weekly backups. Defaults to 4

**KEEP_MONTHLY** - keep specified number of monthly backups. Defaults to 6

### SSHFS

**SSHFS** - sshfs destination in form of `user@host:/path`. When using sshfs, container needs special permissions: `--cap-add SYS_ADMIN --device /dev/fuse` and if using SELinux: `--security-opt label:disable` or apparmor: `--security-opt apparmor:unconfined`

**SSHFS_PASSWORD** - password for ssh authentication

**SSHFS_IDENTITY_FILE** - path to ssh key

**SSHFS_GEN_IDENTITY_FILE** - if set, generates ssh key pair if *SSHFS_IDENTITY_FILE* is set, but the key file doesn't exist. 4096 bits long rsa key will be generated. After generating the key, the public part of the key is printed to stdout and the container stops, so you have the chance to configure the server part before running first backup


