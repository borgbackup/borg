# Borg Docker Image

Docker image with [BorgBackup](https://borgbackup.readthedocs.io/en/stable/)
client utility and sshfs support. Borg is a deduplicating archiver with
compression and authenticated encryption. It's very efficient and doesn't
need regular full backups while still supporting data pruning.

## Quick start

### A step by step example

Before a backup can be made a repository has to be initialized:

```
docker run \
  -v /path/to/host/repo:/path/to/repo \
  borgbackup/borg \
  init --encryption=repokey /path/to/repo
```

Backup the ~/src and ~/Documents directories into an archive called Monday:

```
docker run \
  -v ~/src:/host/src \
  -v ~/Documents:/host/Documents \
  -v /path/to/host/repo:/path/to/repo \
  borgbackup/borg \
  create /path/to/repo::Monday /host/src /host/Documents
```

The next day create a new archive called Tuesday:

```
docker run \
  -v ~/src:/host/src \
  -v ~/Documents:/host/Documents \
  -v /path/to/host/repo:/path/to/repo \
  borgbackup/borg \
  create /path/to/repo::Tuesday /host/src /host/Documents
```

Please read the [quick start](https://borgbackup.readthedocs.io/en/stable/quickstart.html)
from the borg command line to continue this Quick Start.

Note that this example is using the `latest` version of borg, and we recommend you
to pin the version by appending version e.g. `borgbackup/borg:1.0.7` to use `1.0.7`.

## Convenience Scripts

We also ship 2 scripts, follow the links to get instructions:
 - [/usr/bin/borgbackup](./CLIENT.md)
 - [/usr/bin/borgserver](./SERVER.md)

## Contributor 

The backup script comes from the great work of [pschiffe](https://github.com/pschiffe).
