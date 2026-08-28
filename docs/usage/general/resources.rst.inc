Resource Usage
~~~~~~~~~~~~~~

Borg might use significant resources depending on the size of the data set it is dealing with.

If you use Borg in a client/server way (with an SSH repository),
the resource usage occurs partly on the client and partly on the
server.

If you use Borg as a single process (with a filesystem repository),
all resource usage occurs in that one process, so add up client and
server to get the approximate resource usage.

CPU client:
    - **borg create:** chunking, hashing, compression, encryption (high CPU usage)
    - **chunks index rebuild:** quite heavy on CPU, doing lots of hash table operations
    - **borg extract:** decryption, decompression (medium to high CPU usage)
    - **borg prune/borg delete archive:** quick, low CPU usage
    - **borg repo-delete:** low CPU usage, it just removes the repository's objects
    - **borg compact:** medium CPU usage
    - **borg check:** medium CPU usage, but depends on options given

    Most of Borg is single-threaded, but some parts do use more than one CPU core:

    - zstd compresses a chunk multi-threaded by default (only for chunks of at
      least 768 KiB, using at most 4 threads); see ``BORG_ZSTD_MT_WORKERS``.
    - the BLAKE3 based id-hash / MAC modes hash multi-threaded for inputs from
      256 KiB on; see ``BORG_BLAKE3_MT_THRESHOLD``.
    - ``borg create`` hands each finished pack file to a background thread, so
      hashing and storing a pack overlaps with processing the next one.

    Especially higher zlib and lzma compression levels use significant amounts
    of CPU cycles. Crypto might be cheap on the CPU (if hardware-accelerated) or
    expensive (if not).

CPU server:
    It usually does not need much CPU; it just deals with the key/value store
    (repository).

    borg check: the repository check computes the checksums of all chunks
    (medium CPU usage)
    borg compact: low to medium CPU usage

CPU (only for client/server operation):
    When using Borg in a client/server way with an ssh-type repository, the SSH
    processes used for the transport layer will need some CPU on the client and
    on the server due to the crypto they are doing — especially if you are pumping
    large amounts of data.

Memory (RAM) client:
    The chunks index and the files index are read into memory for performance
    reasons. Might need large amounts of memory (see below).
    Compression, especially with high compression levels, might need substantial
    amounts of memory.

Memory (RAM) server:
    Usually rather low memory needs, much less than the client.

Chunks index (client only):
    Proportional to the number of data chunks in your repo. Lots of chunks
    in your repo imply a big chunks index.
    It is possible to tweak the chunker parameters (see create options).

Files index (client only):
    Proportional to the number of files in your last backups. Can be switched
    off (see create options), but the next backup might be much slower if you do.
    The speed benefit of using the files cache is proportional to file size.

Temporary files (client):
    TODO

Temporary files (server):
    TODO

Cache files (client only):
    Contains the files cache, which might become quite large depending on the
    amount and size of files.

Network (only for client/server operation):
    If your repository is remote, all deduplicated (and optionally compressed/
    encrypted) data has to go over the network connection.
