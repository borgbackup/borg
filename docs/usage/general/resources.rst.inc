Resource Usage
~~~~~~~~~~~~~~

Borg might use a lot of resources depending on the size of the data set it is dealing with.

If one uses Borg in a client/server way (with a ssh: repository),
the resource usage occurs in part on the client and in another part on the
server.

If one uses Borg as a single process (with a filesystem repo),
all the resource usage occurs in that one process, so just add up client +
server to get the approximate resource usage.

CPU client:
    - **borg create:** does chunking, hashing, compression, crypto (high CPU usage)
    - **chunks cache sync:** quite heavy on CPU, doing lots of hashtable operations.
    - **borg extract:** crypto, decompression (medium to high CPU usage)
    - **borg check:** similar to extract, but depends on options given.
    - **borg prune / borg delete archive:** low to medium CPU usage
    - **borg delete repo:** done on the server

    It won't go beyond 100% of 1 core as the code is currently single-threaded.
    Especially higher zlib and lzma compression levels use significant amounts
    of CPU cycles. Crypto might be cheap on the CPU (if hardware accelerated) or
    expensive (if not).

CPU server:
    It usually doesn't need much CPU, it just deals with the key/value store
    (repository) and uses the repository index for that.

    borg check: the repository check computes the checksums of all chunks
    (medium CPU usage)
    borg delete repo: low CPU usage

CPU (only for client/server operation):
    When using borg in a client/server way with a ssh:-type repo, the ssh
    processes used for the transport layer will need some CPU on the client and
    on the server due to the crypto they are doing - esp. if you are pumping
    big amounts of data.

Memory (RAM) client:
    The chunks index and the files index are read into memory for performance
    reasons. Might need big amounts of memory (see below).
    Compression, esp. lzma compression with high levels might need substantial
    amounts of memory.

Memory (RAM) server:
    The server process will load the repository index into memory. Might need
    considerable amounts of memory, but less than on the client (see below).

Chunks index (client only):
    Proportional to the amount of data chunks in your repo. Lots of chunks
    in your repo imply a big chunks index.
    It is possible to tweak the chunker params (see create options).

Files index (client only):
    Proportional to the amount of files in your last backups. Can be switched
    off (see create options), but next backup might be much slower if you do.
    The speed benefit of using the files cache is proportional to file size.

Repository index (server only):
    Proportional to the amount of data chunks in your repo. Lots of chunks
    in your repo imply a big repository index.
    It is possible to tweak the chunker params (see create options) to
    influence the amount of chunks being created.

Temporary files (client):
    Reading data and metadata from a FUSE mounted repository will consume up to
    the size of all deduplicated, small chunks in the repository. Big chunks
    won't be locally cached.

Temporary files (server):
    A non-trivial amount of data will be stored on the remote temp directory
    for each client that connects to it. For some remotes, this can fill the
    default temporary directory at /tmp. This can be remediated by ensuring the
    $TMPDIR, $TEMP, or $TMP environment variable is properly set for the sshd
    process.
    For some OSes, this can be done just by setting the correct value in the
    .bashrc (or equivalent login config file for other shells), however in
    other cases it may be necessary to first enable ``PermitUserEnvironment yes``
    in your ``sshd_config`` file, then add ``environment="TMPDIR=/my/big/tmpdir"``
    at the start of the public key to be used in the ``authorized_hosts`` file.

Cache files (client only):
    Contains the chunks index and files index (plus a collection of single-
    archive chunk indexes which might need huge amounts of disk space,
    depending on archive count and size - see FAQ about how to reduce).

Network (only for client/server operation):
    If your repository is remote, all deduplicated (and optionally compressed/
    encrypted) data of course has to go over the connection (``ssh://`` repo url).
    If you use a locally mounted network filesystem, additionally some copy
    operations used for transaction support also go over the connection. If
    you backup multiple sources to one target repository, additional traffic
    happens for cache resynchronization.
