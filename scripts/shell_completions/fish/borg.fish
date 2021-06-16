# Completions for borg
# https://www.borgbackup.org/
# Note:
# Listing archives works on password protected repositories only if $BORG_PASSPHRASE is set.
# Install:
# Copy this file to /usr/share/fish/vendor_completions.d/

# Commands

complete -c borg -f -n __fish_is_first_token -a 'init' -d 'Initialize an empty repository'
complete -c borg -f -n __fish_is_first_token -a 'create' -d 'Create new archive'
complete -c borg -f -n __fish_is_first_token -a 'extract' -d 'Extract archive contents'
complete -c borg -f -n __fish_is_first_token -a 'check' -d 'Check repository consistency'
complete -c borg -f -n __fish_is_first_token -a 'rename' -d 'Rename an existing archive'
complete -c borg -f -n __fish_is_first_token -a 'list' -d 'List archive or repository contents'
complete -c borg -f -n __fish_is_first_token -a 'diff' -d 'Find differences between archives'
complete -c borg -f -n __fish_is_first_token -a 'delete' -d 'Delete a repository or archive'
complete -c borg -f -n __fish_is_first_token -a 'prune' -d 'Prune repository archives'
complete -c borg -f -n __fish_is_first_token -a 'info' -d 'Show archive details'
complete -c borg -f -n __fish_is_first_token -a 'mount' -d 'Mount archive or a repository'
complete -c borg -f -n __fish_is_first_token -a 'umount' -d 'Un-mount the mounted archive'

function __fish_borg_seen_key
    if __fish_seen_subcommand_from key
        and not __fish_seen_subcommand_from import export change-passphrase
        return 0
    end
    return 1
end
complete -c borg -f -n __fish_is_first_token -a 'key' -d 'Manage a repository key'
complete -c borg -f -n __fish_borg_seen_key  -a 'import' -d 'Import a repository key'
complete -c borg -f -n __fish_borg_seen_key  -a 'export' -d 'Export a repository key'
complete -c borg -f -n __fish_borg_seen_key  -a 'change-passphrase' -d 'Change key file passphrase'

complete -c borg -f -n __fish_is_first_token -a 'serve' -d 'Start in server mode'
complete -c borg -f -n __fish_is_first_token -a 'upgrade' -d 'Upgrade a repository'
complete -c borg -f -n __fish_is_first_token -a 'recreate' -d 'Recreate contents of existing archives'
complete -c borg -f -n __fish_is_first_token -a 'export-tar' -d 'Create tarball from an archive'
complete -c borg -f -n __fish_is_first_token -a 'with-lock' -d 'Run a command while repository lock held'
complete -c borg -f -n __fish_is_first_token -a 'break-lock' -d 'Break the repository lock'
complete -c borg -f -n __fish_is_first_token -a 'config' -d 'Get/set options in repo/cache config'

function __fish_borg_seen_benchmark
    if __fish_seen_subcommand_from benchmark
        and not __fish_seen_subcommand_from crud
        return 0
    end
    return 1
end
complete -c borg -f -n __fish_is_first_token -a 'benchmark' -d 'Benchmark borg operations'
complete -c borg -f -n __fish_borg_seen_benchmark -a 'crud' -d 'Benchmark borg CRUD operations'

function __fish_borg_seen_help
    if __fish_seen_subcommand_from help
        and not __fish_seen_subcommand_from patterns placeholders compression
        return 0
    end
    return 1
end
complete -c borg -f -n __fish_is_first_token -a 'help' -d 'Miscellaneous Help'
complete -c borg -f -n __fish_borg_seen_help -a 'patterns' -d 'Help for patterns'
complete -c borg -f -n __fish_borg_seen_help -a 'placeholders' -d 'Help for placeholders'
complete -c borg -f -n __fish_borg_seen_help -a 'compression' -d 'Help for compression'

# Common options
complete -c borg -f -s h -l 'help'                  -d 'Show help information'
complete -c borg -f      -l 'version'               -d 'Show version information'
complete -c borg -f      -l 'critical'              -d 'Log level CRITICAL'
complete -c borg -f      -l 'error'                 -d 'Log level ERROR'
complete -c borg -f      -l 'warning'               -d 'Log level WARNING (default)'
complete -c borg -f      -l 'info'                  -d 'Log level INFO'
complete -c borg -f -s v -l 'verbose'               -d 'Log level INFO'
complete -c borg -f      -l 'debug'                 -d 'Log level DEBUG'
complete -c borg -f      -l 'debug-topic'           -d 'Enable TOPIC debugging'
complete -c borg -f -s p -l 'progress'              -d 'Show progress information'
complete -c borg -f      -l 'log-json'              -d 'Output one JSON object per log line'
complete -c borg -f      -l 'lock-wait'             -d 'Wait for lock max N seconds [1]'
complete -c borg -f      -l 'show-version'          -d 'Log version information'
complete -c borg -f      -l 'show-rc'               -d 'Log the return code'
complete -c borg -f      -l 'umask'                 -d 'Set umask to M [0077]'
complete -c borg         -l 'remote-path'           -d 'Use PATH as remote borg executable'
complete -c borg -f      -l 'remote-ratelimit'      -d 'Set remote network upload RATE limit'
complete -c borg -f      -l 'consider-part-files'   -d 'Treat part files like normal files'
complete -c borg         -l 'debug-profile'         -d 'Write execution profile into FILE'
complete -c borg         -l 'rsh'                   -d 'Use COMMAND instead of ssh'

# borg init options
set -l encryption_modes "none keyfile keyfile-blake2 repokey repokey-blake2 authenticated authenticated-blake2"
complete -c borg -f -s e -l 'encryption'            -d 'Encryption key MODE' -a "$encryption_modes" -n "__fish_seen_subcommand_from init"
complete -c borg -f      -l 'append-only'           -d 'Create an append-only mode repository'      -n "__fish_seen_subcommand_from init"
complete -c borg -f      -l 'storage-quota'         -d 'Set storage QUOTA of the repository'        -n "__fish_seen_subcommand_from init"
complete -c borg -f      -l 'make-parent-dirs'      -d 'Create parent directories'                  -n "__fish_seen_subcommand_from init"

# borg create options
complete -c borg -f -s n -l 'dry-run'               -d 'Do not change the repository'                       -n "__fish_seen_subcommand_from create"
complete -c borg -f -s s -l 'stats'                 -d 'Print verbose statistics'                           -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'list'                  -d 'Print verbose list of items'                        -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'filter'                -d 'Only items with given STATUSCHARS'                  -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'json'                  -d 'Print verbose stats as json'                        -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'no-cache-sync'         -d 'Do not synchronize the cache'                       -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'stdin-name'            -d 'Use NAME in archive for stdin data'                 -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'stdin-user'            -d 'Set user USER in archive for stdin data [root]'     -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'stdin-group'           -d 'Set group GROUP in archive for stdin data [root]'   -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'stdin-mode'            -d 'Set mode to M in archive for stdin data [0660]'     -n "__fish_seen_subcommand_from create"

# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from create"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from create"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'exclude-caches'        -d 'Exclude directories tagged as cache'        -n "__fish_seen_subcommand_from create"
complete -c borg         -l 'exclude-if-present'    -d 'Exclude directories that contain FILENAME'  -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'keep-exclude-tags'     -d 'Keep tag files of excluded directories'     -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'keep-tag-files'        -d 'Keep tag files of excluded directories'     -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'exclude-nodump'        -d 'Exclude files flagged NODUMP'               -n "__fish_seen_subcommand_from create"
# Filesystem options
complete -c borg -f -s x -l 'one-file-system'       -d 'Stay in the same file system'               -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'numeric-owner'         -d 'Only store numeric user:group identifiers'  -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'noatime'               -d 'Do not store atime'                         -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'noctime'               -d 'Do not store ctime'                         -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'nobirthtime'           -d 'Do not store creation date'                 -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'nobsdflags'            -d 'Do not store bsdflags'                      -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'ignore-inode'          -d 'Ignore inode data in file metadata cache'   -n "__fish_seen_subcommand_from create"
set -l files_cache_mode "ctime,size,inode mtime,size,inode ctime,size mtime,size rechunk,ctime rechunk,mtime disabled"
complete -c borg -f      -l 'files-cache'           -d 'Operate files cache in MODE' -a "$files_cache_mode" -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'read-special'          -d 'Open device files like regular files'       -n "__fish_seen_subcommand_from create"
# Archive options
complete -c borg -f      -l 'comment'               -d 'Add COMMENT to the archive'                 -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'timestamp'             -d 'Set creation TIME (yyyy-mm-ddThh:mm:ss)'    -n "__fish_seen_subcommand_from create"
complete -c borg         -l 'timestamp'             -d 'Set creation time by reference FILE'        -n "__fish_seen_subcommand_from create"
complete -c borg -f -s c -l 'checkpoint-interval'   -d 'Write checkpoint every N seconds [1800]'    -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'chunker-params'        -d 'Chunker PARAMETERS [19,23,21,4095]'         -n "__fish_seen_subcommand_from create"
set -l compression_methods "none auto lz4 zstd,1 zstd,2 zstd,3 zstd,4 zstd,5 zstd,6 zstd,7 zstd,8 zstd,9 zstd,10 zstd,11 zstd,12 zstd,13 zstd,14 zstd,15 zstd,16 zstd,17 zstd,18 zstd,19 zstd,20 zstd,21 zstd,22 zlib,1 zlib,2 zlib,3 zlib,4 zlib,5 zlib,6 zlib,7 zlib,8 zlib,9 lzma,0 lzma,1 lzma,2 lzma,3 lzma,4 lzma,5 lzma,6 lzma,7 lzma,8 lzma,9"
complete -c borg -f -s C -l 'compression'           -d 'Select compression ALGORITHM,LEVEL [lz4]' -a "$compression_methods" -n "__fish_seen_subcommand_from create"

# borg extract options
complete -c borg -f      -l 'list'                  -d 'Print verbose list of items'                -n "__fish_seen_subcommand_from extract"
complete -c borg -f -s n -l 'dry-run'               -d 'Do not actually extract any files'          -n "__fish_seen_subcommand_from extract"
complete -c borg -f      -l 'numeric-owner'         -d 'Only obey numeric user:group identifiers'   -n "__fish_seen_subcommand_from extract"
complete -c borg -f      -l 'nobsdflags'            -d 'Do not extract/set bsdflags'                -n "__fish_seen_subcommand_from extract"
complete -c borg -f      -l 'stdout'                -d 'Write all extracted data to stdout'         -n "__fish_seen_subcommand_from extract"
complete -c borg -f      -l 'sparse'                -d 'Create holes in output sparse file'         -n "__fish_seen_subcommand_from extract"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from extract"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from extract"
complete -c borg         -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from extract"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from extract"
complete -c borg -f      -l 'strip-components'      -d 'Remove NUMBER of leading path elements'     -n "__fish_seen_subcommand_from extract"

# borg check options
complete -c borg -f      -l 'repository-only'       -d 'Only perform repository checks'             -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'archives-only'         -d 'Only perform archives checks'               -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'verify-data'           -d 'Cryptographic integrity verification'       -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'repair'                -d 'Attempt to repair found inconsistencies'    -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'save-space'            -d 'Work slower but using less space'           -n "__fish_seen_subcommand_from check"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from check"
complete -c borg -f -s a -l 'glob-archives'         -d 'Only archive names matching GLOB'           -n "__fish_seen_subcommand_from check"
set -l sort_keys "timestamp name id"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from check"

# borg rename
# no specific options

# borg list options
complete -c borg -f      -l 'short'                 -d 'Only print file/directory names'            -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'list-format'           -d 'Specify FORMAT for file listing'            -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'format'                -d 'Specify FORMAT for file listing'            -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'json'                  -d 'List contents in json format'               -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'json-lines'            -d 'List contents in json lines format'         -n "__fish_seen_subcommand_from list"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from list"
complete -c borg -f -s a -l 'glob-archives'         -d 'Only archive names matching GLOB'           -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from list"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from list"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from list"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from list"

# borg diff options
complete -c borg -f      -l 'numeric-owner'         -d 'Only consider numeric user:group'           -n "__fish_seen_subcommand_from diff"
complete -c borg -f      -l 'same-chunker-params'   -d 'Override check of chunker parameters'       -n "__fish_seen_subcommand_from diff"
complete -c borg -f      -l 'sort'                  -d 'Sort the output lines by file path'         -n "__fish_seen_subcommand_from diff"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from diff"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from diff"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from diff"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from diff"

# borg delete options
complete -c borg -f -s n -l 'dry-run'               -d 'Do not change the repository'               -n "__fish_seen_subcommand_from delete"
complete -c borg -f -s s -l 'stats'                 -d 'Print verbose statistics'                   -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'cache-only'            -d "Delete only the local cache"                -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'force'                 -d 'Force deletion of corrupted archives'       -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'save-space'            -d 'Work slower but using less space'           -n "__fish_seen_subcommand_from delete"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from delete"
complete -c borg -f -s a -l 'glob-archives'         -d 'Only archive names matching GLOB'           -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from delete"

# borg prune options
complete -c borg -f -s n -l 'dry-run'               -d 'Do not change the repository'               -n "__fish_seen_subcommand_from prune"
complete -c borg -f      -l 'force'                 -d 'Force pruning of corrupted archives'        -n "__fish_seen_subcommand_from prune"
complete -c borg -f -s s -l 'stats'                 -d 'Print verbose statistics'                   -n "__fish_seen_subcommand_from prune"
complete -c borg -f      -l 'list'                  -d 'Print verbose list of items'                -n "__fish_seen_subcommand_from prune"
complete -c borg -f      -l 'keep-within'           -d 'Keep archives within time INTERVAL'         -n "__fish_seen_subcommand_from prune"
complete -c borg -f      -l 'keep-last'             -d 'NUMBER of secondly archives to keep'        -n "__fish_seen_subcommand_from prune"
complete -c borg -f      -l 'keep-secondly'         -d 'NUMBER of secondly archives to keep'        -n "__fish_seen_subcommand_from prune"
complete -c borg -f      -l 'keep-minutely'         -d 'NUMBER of minutely archives to keep'        -n "__fish_seen_subcommand_from prune"
complete -c borg -f -s H -l 'keep-hourly'           -d 'NUMBER of hourly archives to keep'          -n "__fish_seen_subcommand_from prune"
complete -c borg -f -s d -l 'keep-daily'            -d 'NUMBER of daily archives to keep'           -n "__fish_seen_subcommand_from prune"
complete -c borg -f -s w -l 'keep-weekly'           -d 'NUMBER of weekly archives to keep'          -n "__fish_seen_subcommand_from prune"
complete -c borg -f -s m -l 'keep-monthly'          -d 'NUMBER of monthly archives to keep'         -n "__fish_seen_subcommand_from prune"
complete -c borg -f -s y -l 'keep-yearly'           -d 'NUMBER of yearly archives to keep'          -n "__fish_seen_subcommand_from prune"
complete -c borg -f      -l 'save-space'            -d 'Work slower but using less space'           -n "__fish_seen_subcommand_from prune"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from prune"
complete -c borg -f -s a -l 'glob-archives'         -d 'Only archive names matching GLOB'           -n "__fish_seen_subcommand_from prune"

# borg info options
complete -c borg -f      -l 'json'                  -d 'Format output in json format'               -n "__fish_seen_subcommand_from info"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from info"
complete -c borg -f -s a -l 'glob-archives'         -d 'Only archive names matching GLOB'           -n "__fish_seen_subcommand_from info"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from info"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from info"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from info"

# borg mount options
complete -c borg -f -s f -l 'foreground'            -d 'Stay in foreground, do not daemonize'       -n "__fish_seen_subcommand_from mount"
# FIXME This list is probably not full, but I tried to pick only those that are relevant to borg mount -o:
set -l fuse_options "ac_attr_timeout= allow_damaged_files allow_other allow_root attr_timeout= auto auto_cache auto_unmount default_permissions entry_timeout= gid= group_id= kernel_cache max_read= negative_timeout= noauto noforget remember= remount rootmode= uid= umask= user user_id= versions"
complete -c borg -f -s o                            -d 'Fuse mount OPTION' -a "$fuse_options"       -n "__fish_seen_subcommand_from mount"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from mount"
complete -c borg -f -s a -l 'glob-archives'         -d 'Only archive names matching GLOB'           -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from mount"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from mount"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from mount"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'strip-components'      -d 'Remove NUMBER of leading path elements'     -n "__fish_seen_subcommand_from mount"

# borg umount
# no specific options

# borg key change-passphrase
# no specific options

# borg key export
complete -c borg -f      -l 'paper'                 -d 'Create an export for printing'              -n "__fish_seen_subcommand_from export"
complete -c borg -f      -l 'qr-html'               -d 'Create an html file for printing and qr'    -n "__fish_seen_subcommand_from export"

# borg key import
complete -c borg -f      -l 'paper'                 -d 'Import from a backup done with --paper'     -n "__fish_seen_subcommand_from import"

# borg upgrade
complete -c borg -f -s n -l 'dry-run'               -d 'Do not change the repository'               -n "__fish_seen_subcommand_from upgrade"
complete -c borg -f      -l 'inplace'               -d 'Rewrite repository in place'                -n "__fish_seen_subcommand_from upgrade"
complete -c borg -f      -l 'force'                 -d 'Force upgrade'                              -n "__fish_seen_subcommand_from upgrade"
complete -c borg -f      -l 'tam'                   -d 'Enable manifest authentication'             -n "__fish_seen_subcommand_from upgrade"
complete -c borg -f      -l 'disable-tam'           -d 'Disable manifest authentication'            -n "__fish_seen_subcommand_from upgrade"

# borg recreate
complete -c borg -f      -l 'list'                  -d 'Print verbose list of items'                -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'filter'                -d 'Only items with given STATUSCHARS'          -n "__fish_seen_subcommand_from recreate"
complete -c borg -f -s n -l 'dry-run'               -d 'Do not change the repository'               -n "__fish_seen_subcommand_from recreate"
complete -c borg -f -s s -l 'stats'                 -d 'Print verbose statistics'                   -n "__fish_seen_subcommand_from recreate"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from recreate"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from recreate"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'exclude-caches'        -d 'Exclude directories tagged as cache'        -n "__fish_seen_subcommand_from recreate"
complete -c borg         -l 'exclude-if-present'    -d 'Exclude directories that contain FILENAME'  -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'keep-exclude-tags'     -d 'Keep tag files of excluded directories'     -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'keep-tag-files'        -d 'Keep tag files of excluded directories'     -n "__fish_seen_subcommand_from recreate"
# Archive options
complete -c borg -f      -l 'target'                -d "Create a new ARCHIVE"                       -n "__fish_seen_subcommand_from recreate"
complete -c borg -f -s c -l 'checkpoint-interval'   -d 'Write checkpoint every N seconds [1800]'    -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'comment'               -d 'Add COMMENT to the archive'                 -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'timestamp'             -d 'Set creation TIME (yyyy-mm-ddThh:mm:ss)'    -n "__fish_seen_subcommand_from recreate"
complete -c borg         -l 'timestamp'             -d 'Set creation time using reference FILE'     -n "__fish_seen_subcommand_from recreate"
complete -c borg -f -s C -l 'compression'           -d 'Select compression ALGORITHM,LEVEL [lz4]' -a "$compression_methods" -n "__fish_seen_subcommand_from recreate"
set -l recompress_when "if-different always never"
complete -c borg -f      -l 'recompress'            -d 'Recompress chunks CONDITION' -a "$recompress_when" -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'chunker-params'        -d 'Chunker PARAMETERS [19,23,21,4095]'         -n "__fish_seen_subcommand_from recreate"

# borg export-tar options
complete -c borg         -l 'tar-filter'            -d 'Filter program to pipe data through'        -n "__fish_seen_subcommand_from export-tar"
complete -c borg -f      -l 'list'                  -d 'Print verbose list of items'                -n "__fish_seen_subcommand_from export-tar"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from recreate"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from recreate"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'strip-components'      -d 'Remove NUMBER of leading path elements'     -n "__fish_seen_subcommand_from recreate"

# borg serve
complete -c borg         -l 'restrict-to-path'      -d 'Restrict repository access to PATH'         -n "__fish_seen_subcommand_from serve"
complete -c borg         -l 'restrict-to-repository' -d 'Restrict repository access at PATH'        -n "__fish_seen_subcommand_from serve"
complete -c borg -f      -l 'append-only'           -d 'Only allow appending to repository'         -n "__fish_seen_subcommand_from serve"
complete -c borg -f      -l 'storage-quota'         -d 'Override storage QUOTA of the repository'   -n "__fish_seen_subcommand_from serve"

# borg config
complete -c borg -f -s c -l 'cache'                 -d 'Get/set/list values in the repo cache'      -n "__fish_seen_subcommand_from config"
complete -c borg -f -s d -l 'delete'                -d 'Delete the KEY from the config'             -n "__fish_seen_subcommand_from config"
complete -c borg -f      -l 'list'                  -d 'List the configuration of the repo'         -n "__fish_seen_subcommand_from config"

# borg with-lock
# no specific options

# borg break-lock
# no specific options

# borg benchmark
# no specific options

# borg help
# no specific options


# List repositories::archives

function __fish_borg_is_argument_n --description 'Test if current argument is on Nth place' --argument n
    set tokens (commandline --current-process --tokenize --cut-at-cursor)
    set -l tokencount 0
    for token in $tokens
        switch $token
            case '-*'
                # ignore command line switches
            case '*'
                set tokencount (math $tokencount+1)
        end
    end
    return (test $tokencount -eq $n)
end

function __fish_borg_is_dir_a_repository
    set -l config_content
    if test -f $argv[1]/README
    and test -f $argv[1]/config
        read config_content < $argv[1]/config ^/dev/null
    end
    return (string match --quiet '[repository]' $config_content)
end

function __fish_borg_list_repos_or_archives
    if string match --quiet --regex '.*::' '"'(commandline --current-token)'"'
        # If the current token contains "::" then list the archives:
        set -l repository_name (string replace --regex '::.*' '' (commandline --current-token))
        borg list --format="$repository_name::{archive}{TAB}{comment}{NEWLINE}" "$repository_name" ^/dev/null
    else
        # Otherwise list the repositories, directories and user@host entries:
        set -l directories (commandline --cut-at-cursor --current-token)*/
        for directoryname in $directories
            if __fish_borg_is_dir_a_repository $directoryname
                printf '%s::\t%s\n' (string trim --right --chars='/' $directoryname) "Repository"
            else
                printf '%s\n' $directoryname
            end
        end
        __fish_complete_user_at_hosts | string replace --regex '$' ':'
    end
end

complete -c borg -f -n "__fish_borg_is_argument_n 2" -a '(__fish_borg_list_repos_or_archives)'


# Additional archive listings

function __fish_borg_is_diff_second_archive
    return (string match --quiet --regex ' diff .*::[^ ]+ '(commandline --current-token)'$' (commandline))
end

function __fish_borg_is_delete_additional_archive
    return (string match --quiet --regex ' delete .*::[^ ]+ ' (commandline))
end

function __fish_borg_list_only_archives
    set -l repo_matches (string match --regex '([^ ]*)::' (commandline))
    borg list --format="{archive}{TAB}{comment}{NEWLINE}" "$repo_matches[2]" ^/dev/null
end

complete -c borg -f -n __fish_borg_is_diff_second_archive -a '(__fish_borg_list_only_archives)'
complete -c borg -f -n __fish_borg_is_delete_additional_archive -a '(__fish_borg_list_only_archives)'
