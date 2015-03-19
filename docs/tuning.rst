.. _tuning:
.. include:: global.rst.inc

Tuning
======

General hints
-------------
CPU load, backup speed, memory and storage usage are covered below.

As performance and resource usage depend on a lot of factors, you may need to
tweak the parameters a bit and retry until you found the best ones for your
setup.

Usually, the default parameters are selected for best speed under the assumption
that you run a modern machine with fast CPU, fast I/O and a good amount of RAM.

If you run an older or low-resource machine or your backup target or connection
to it is slow, tweaking parameters might give significant speedups.

Exclude crap data
-----------------
Maybe you don't want to backup:

* cache / temporary files (they can be rebuilt / are useless)
* specific directories / filenames / file extensions you do not need
* backups (some people make backups of backups...)

You can exclude these, so they don't waste time and space.

Avoid scrolling
---------------
If you do benchmarks, avoid creating a lot of log output, especially if it
means scrolling text in a window on a graphical user interface.

Rather use much less log output or at least redirect the output to a log file,
that is also much faster than scrolling.

Speed (in general)
------------------
Keep an eye on CPU and I/O bounds. Try to find the sweet spot in the middle
where it is not too much I/O bound and not too much CPU bound.

I/O bound
~~~~~~~~~
If CPU load does not sum up to 1 core fully loaded while backing up, the
process is likely I/O bound (can't read or write data fast enough).

Maybe you want to try higher compression then so it has less data to write.
Or get faster I/O, if possible.

CPU bound
~~~~~~~~~
If you have 1 core fully loaded most of the time, but your backup seems slow,
the process is likely CPU bound (can't compute fast enough).

Maybe you want to try lower compression then so it has less to compute.
Using a faster MAC or cipher method might also be an option.
Or get a faster CPU.

I/O speed
---------
From fast to slower:

* fast local filesystem, SSD or HDD, via PCIe, SATA, USB
* ssh connection to a remote server's attic instance
* mounted network filesystems of a remote server

Not only throughput influences timing, latency does also.

Backup space needed
-------------------
If you always backup the same data mostly, you will often save a lot of space
due to deduplication - this works independently from compression.

To avoid running out of space, regularly prune your backup archives according
to your needs. Backups of same machine which are close in time are usually
very cheap (because most data is same and deduplicated).

Compression
-----------
If you have a fast backup source and destination and you are not low on backup space:
Switch off compression, your backup will run faster and with less cpu load.

If you just want to save a bit space, but stay relatively fast:
Try zlib level 1.

If you have very slow source or destination (e.g. a remote backup space via a
network connection that is quite slower than your local and remote storage):
Try a higher zlib or lzma.

Authentication & MAC selection
------------------------------
Real MACs (Message Authentication Codes) can only be used when a secret key is
available. It is signing your backup data and can detect malicious tampering.
Without a key, a simple hash will be used (which helps to detect accidental
data corruption, but can not detect malicious data tampering).

Older or simple 32bit machine architecture
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use sha256 (no key) or hmac-sha256 (key).

64bit architecture, but no AES hardware acceleration in the CPU
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use sha512-256 (no key) or hmac-sha512-256 (key).

Modern 64bit CPU with AES hardware acceleration (AES-NI, PCLMULQDQ)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use ghash (no key) or gmac (key).

Encryption & Cipher selection
-----------------------------
Always encrypt your backups (and keep passphrase and key file [if any] safe).

The cipher selection chooses between misc. AEAD ciphers (authenticated
encryption with associated data), it is EtM (encrypt-then-mac):

Older or simple 32bit machine architecture
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use aes256-ctr + hmac-sha256.

64bit architecture, but no AES hardware acceleration in the CPU
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use aes256-ctr + hmac-sha512-256.

Modern 64bit CPU with AES hardware acceleration (AES-NI, PCLMULQDQ)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Use aes256-gcm (AEAD 1-pass cipher).

RAM usage
---------
Depending on the amount of files and chunks in the repository, memory usage
varies:

* about 250+B RAM per file (for "files" cache)
* about 44B RAM per 64kiB chunk (for "chunks" cache)
* about 40B RAM per 64kiB chunk (for repository index, if remote repo is used,
  this will be allocated on remote side)

If you run into memory usage issues, your options are:

* get more RAM (or more swapspace, speed will be slower)
* disable the "files" cache, speed will be slower
* have less files / chunks per repo

Note: RAM compression likely won't help as a lot of that data is using
msgpack, which is already rather efficient.
