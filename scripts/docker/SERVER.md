## Server side

The state of this document and the associated script is beta, please use with caution.

To start a borg server:
 - generate an ssh-key
   - `ssh-keygen -f ./id_rsa -N '' -t rsa`
 - choose where to store ssh details
 - choose where to store backup data

and run the following command:

```
docker run \
  -e SSH_KEY=... \
  -v /path/to/ssh/folder:/etc/ssh \
  -v /path/to/local/folder:/backups \
  --entrypoint=/usr/bin/borgserver \
  borgbackup/borg
```
