# Completions for borg
# https://www.borgbackup.org/
# Note:
# Listing archives works on password protected repositories only if $BORG_PASSPHRASE is set.
# Install:
# Copy this file to /usr/share/fish/vendor_completions.d/

# Commands

complete -c borg -f -n __fish_is_first_token -a 'analyze' -d 'Analyze archives to find "hot spots"'
complete -c borg -f -n __fish_is_first_token -a 'create' -d 'Create a new archive'
complete -c borg -f -n __fish_is_first_token -a 'extract' -d 'Extract archive contents'
complete -c borg -f -n __fish_is_first_token -a 'check' -d 'Check repository consistency'
complete -c borg -f -n __fish_is_first_token -a 'rename' -d 'Rename an existing archive'
complete -c borg -f -n __fish_is_first_token -a 'list' -d 'List archive or repository contents'
complete -c borg -f -n __fish_is_first_token -a 'diff' -d 'Find differences between archives'
complete -c borg -f -n __fish_is_first_token -a 'delete' -d 'Delete an archive'
complete -c borg -f -n __fish_is_first_token -a 'prune' -d 'Prune repository archives'
complete -c borg -f -n __fish_is_first_token -a 'compact' -d 'Free repository space'
complete -c borg -f -n __fish_is_first_token -a 'info' -d 'Show archive details'
complete -c borg -f -n __fish_is_first_token -a 'mount' -d 'Mount archive or a repository'
complete -c borg -f -n __fish_is_first_token -a 'umount' -d 'Un-mount the mounted archive'
complete -c borg -f -n __fish_is_first_token -a 'repo-compress' -d 'Repository (re-)compression'
complete -c borg -f -n __fish_is_first_token -a 'repo-create' -d 'Create a new, empty repository'
complete -c borg -f -n __fish_is_first_token -a 'repo-delete' -d 'Delete a repository'
complete -c borg -f -n __fish_is_first_token -a 'repo-info' -d 'Show repository information'
complete -c borg -f -n __fish_is_first_token -a 'repo-list' -d 'List repository contents'
complete -c borg -f -n __fish_is_first_token -a 'repo-space' -d 'Manage reserved space in a repository'
complete -c borg -f -n __fish_is_first_token -a 'tag' -d 'Tag archives'
complete -c borg -f -n __fish_is_first_token -a 'transfer' -d 'Transfer of archives from another repository'
complete -c borg -f -n __fish_is_first_token -a 'undelete' -d 'Undelete archives'
complete -c borg -f -n __fish_is_first_token -a 'version' -d 'Display borg client version / borg server version'

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
complete -c borg -f -n __fish_is_first_token -a 'recreate' -d 'Recreate contents of existing archives'
complete -c borg -f -n __fish_is_first_token -a 'export-tar' -d 'Create tarball from an archive'
complete -c borg -f -n __fish_is_first_token -a 'with-lock' -d 'Run a command while repository lock held'
complete -c borg -f -n __fish_is_first_token -a 'break-lock' -d 'Break the repository lock'

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
complete -c borg -f      -l 'iec'                   -d 'Format using IEC units (1KiB = 1024B)'
complete -c borg -f      -l 'log-json'              -d 'Output one JSON object per log line'
complete -c borg -f      -l 'lock-wait'             -d 'Wait for lock max N seconds [1]'
complete -c borg -f      -l 'show-version'          -d 'Log version information'
complete -c borg -f      -l 'show-rc'               -d 'Log the return code'
complete -c borg -f      -l 'umask'                 -d 'Set umask to M [0077]'
complete -c borg         -l 'remote-path'           -d 'Use PATH as remote borg executable'
complete -c borg -f      -l 'upload-ratelimit'      -d 'Set network upload rate limit in kiByte/s'
complete -c borg -f      -l 'upload-buffer'         -d 'Set network upload buffer size in MiB'
complete -c borg         -l 'debug-profile'         -d 'Write execution profile into FILE'
complete -c borg         -l 'rsh'                   -d 'Use COMMAND instead of ssh'
complete -c borg         -l 'socket'                -d 'Use UNIX DOMAIN socket at PATH'

# borg analyze options
complete -c borg -f -s a -l 'match-archives'        -d 'Only archive names matching PATTERN'        -n "__fish_seen_subcommand_from analyze"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from analyze"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from analyze"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from analyze"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from analyze"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from analyze"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from analyze"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from analyze"

# borg repo-compress options
# Define compression methods once at the top
set -l compression_methods "none auto lz4 zstd,1 zstd,2 zstd,3 zstd,4 zstd,5 zstd,6 zstd,7 zstd,8 zstd,9 zstd,10 zstd,11 zstd,12 zstd,13 zstd,14 zstd,15 zstd,16 zstd,17 zstd,18 zstd,19 zstd,20 zstd,21 zstd,22 zlib,1 zlib,2 zlib,3 zlib,4 zlib,5 zlib,6 zlib,7 zlib,8 zlib,9 lzma,0 lzma,1 lzma,2 lzma,3 lzma,4 lzma,5 lzma,6 lzma,7 lzma,8 lzma,9"
complete -c borg -f -s C -l 'compression'           -d 'Select compression ALGORITHM,LEVEL [lz4]' -a "$compression_methods" -n "__fish_seen_subcommand_from repo-compress"
complete -c borg -f -s s -l 'stats'                 -d 'Print statistics'                            -n "__fish_seen_subcommand_from repo-compress"

# borg create options
complete -c borg -f -s n -l 'dry-run'               -d 'Do not create a backup archive'                 -n "__fish_seen_subcommand_from create"
complete -c borg -f -s s -l 'stats'                 -d 'Print verbose statistics'                       -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'list'                  -d 'Print verbose list of items'                    -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'filter'                -d 'Only items with given STATUSCHARS'              -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'json'                  -d 'Print verbose stats as json'                    -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'stdin-name'            -d 'Use NAME in archive for stdin data'             -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'content-from-command'  -d 'Interpret PATH as command and store its stdout' -n "__fish_seen_subcommand_from create"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'                 -n "__fish_seen_subcommand_from create"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'         -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'         -n "__fish_seen_subcommand_from create"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'         -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'exclude-caches'        -d 'Exclude directories tagged as cache'            -n "__fish_seen_subcommand_from create"
complete -c borg         -l 'exclude-if-present'    -d 'Exclude directories that contain FILENAME'      -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'keep-exclude-tags'     -d 'Keep tag files of excluded directories'         -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'exclude-nodump'        -d 'Exclude files flagged NODUMP'                   -n "__fish_seen_subcommand_from create"
# Filesystem options
complete -c borg -f -s x -l 'one-file-system'       -d 'Stay in the same file system'                   -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'numeric-ids'           -d 'Only store numeric user:group identifiers'      -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'noatime'               -d 'Do not store atime'                             -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'noctime'               -d 'Do not store ctime'                             -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'nobirthtime'           -d 'Do not store creation date'                     -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'nobsdflags'            -d 'Do not store bsdflags'                          -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'noacls'                -d 'Do not read and store ACLs into archive'        -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'noxattrs'              -d 'Do not read and store xattrs into archive'      -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'noflags'               -d 'Do not store flags'                             -n "__fish_seen_subcommand_from create"
set -l files_cache_mode "ctime,size,inode mtime,size,inode ctime,size mtime,size rechunk,ctime rechunk,mtime size disabled"
complete -c borg -f      -l 'files-cache'           -d 'Operate files cache in MODE' -a "$files_cache_mode" -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'read-special'          -d 'Open device files like regular files'           -n "__fish_seen_subcommand_from create"
# Archive options
complete -c borg -f      -l 'comment'               -d 'Add COMMENT to the archive'                     -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'timestamp'             -d 'Set creation TIME (yyyy-mm-ddThh:mm:ss)'        -n "__fish_seen_subcommand_from create"
complete -c borg         -l 'timestamp'             -d 'Set creation time by reference FILE'            -n "__fish_seen_subcommand_from create"
complete -c borg -f      -l 'chunker-params'        -d 'Chunker PARAMETERS [19,23,21,4095]'             -n "__fish_seen_subcommand_from create"
complete -c borg -f -s C -l 'compression'           -d 'Select compression ALGORITHM,LEVEL [lz4]' -a "$compression_methods" -n "__fish_seen_subcommand_from create"

# borg extract options
complete -c borg -f      -l 'list'                  -d 'Print verbose list of items'                -n "__fish_seen_subcommand_from extract"
complete -c borg -f -s n -l 'dry-run'               -d 'Do not actually extract any files'          -n "__fish_seen_subcommand_from extract"
complete -c borg -f      -l 'numeric-ids'           -d 'Only obey numeric user:group identifiers'   -n "__fish_seen_subcommand_from extract"
complete -c borg -f      -l 'nobsdflags'            -d 'Do not extract/set bsdflags'                -n "__fish_seen_subcommand_from extract"
complete -c borg -f      -l 'noflags'               -d 'Do not extract/set flags'                   -n "__fish_seen_subcommand_from extract"
complete -c borg -f      -l 'noacls'                -d 'Do not extract/set ACLs'                    -n "__fish_seen_subcommand_from extract"
complete -c borg -f      -l 'noxattrs'              -d 'Do not extract/set xattrs'                  -n "__fish_seen_subcommand_from extract"
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
complete -c borg -f      -l 'max-duration'          -d 'Partial repo check for max. SECONDS'        -n "__fish_seen_subcommand_from check"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from check"
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from check"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from check"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from check"

# borg rename
# no specific options

# borg list options
complete -c borg -f      -l 'short'                 -d 'Only print file/directory names'            -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'format'                -d 'Specify FORMAT for file listing'            -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'json'                  -d 'List contents in json format'               -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'json-lines'            -d 'List contents in json lines format'         -n "__fish_seen_subcommand_from list"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from list"
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from list"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from list"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from list"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from list"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from list"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from list"

# borg diff options
complete -c borg -f      -l 'numeric-ids'           -d 'Only consider numeric user:group'           -n "__fish_seen_subcommand_from diff"
complete -c borg -f      -l 'same-chunker-params'   -d 'Override check of chunker parameters'       -n "__fish_seen_subcommand_from diff"
complete -c borg -f      -l 'sort'                  -d 'Sort the output lines by file path'         -n "__fish_seen_subcommand_from diff"
complete -c borg -f      -l 'json-lines'            -d 'Format output as JSON Lines'                -n "__fish_seen_subcommand_from diff"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from diff"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from diff"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from diff"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from diff"

# borg delete options
complete -c borg -f -s n -l 'dry-run'               -d 'Do not change the repository'               -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'list'                  -d 'Output verbose list of archives'              -n "__fish_seen_subcommand_from delete"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from delete"
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from delete"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from delete"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from delete"

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
complete -c borg -f      -l 'keep-13weekly'         -d 'NUMBER of quarterly archives to keep (13 week strategy)' -n "__fish_seen_subcommand_from prune"
complete -c borg -f      -l 'keep-3monthly'         -d 'NUMBER of quarterly archives to keep (3 month strategy)' -n "__fish_seen_subcommand_from prune"
complete -c borg -f -s y -l 'keep-yearly'           -d 'NUMBER of yearly archives to keep'          -n "__fish_seen_subcommand_from prune"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from prune"
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from prune"

# borg compact options
complete -c borg -f -s n -l 'dry-run'               -d 'Do nothing'                                  -n "__fish_seen_subcommand_from compact"
complete -c borg -f -s s -l 'stats'                 -d 'Print statistics (might be much slower)'     -n "__fish_seen_subcommand_from compact"

# borg info options
complete -c borg -f      -l 'json'                  -d 'Format output in json format'               -n "__fish_seen_subcommand_from info"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from info"
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from info"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from info"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from info"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from info"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from info"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from info"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from info"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from info"

# borg repo-list options
complete -c borg -f      -l 'short'                 -d 'Only print the archive IDs, nothing else'   -n "__fish_seen_subcommand_from repo-list"
complete -c borg -f      -l 'format'                -d 'Specify format for archive listing'         -n "__fish_seen_subcommand_from repo-list"
complete -c borg -f      -l 'json'                  -d 'Format output as JSON'                      -n "__fish_seen_subcommand_from repo-list"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from repo-list"
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from repo-list"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from repo-list"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from repo-list"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from repo-list"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from repo-list"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from repo-list"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from repo-list"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from repo-list"
complete -c borg -f      -l 'deleted'               -d 'Consider only soft-deleted archives'        -n "__fish_seen_subcommand_from repo-list"

# borg mount options
complete -c borg -f -s f -l 'foreground'            -d 'Stay in foreground, do not daemonize'       -n "__fish_seen_subcommand_from mount"
# FIXME This list is probably not full, but I tried to pick only those that are relevant to borg mount -o:
set -l fuse_options "ac_attr_timeout= allow_damaged_files allow_other allow_root attr_timeout= auto auto_cache auto_unmount default_permissions entry_timeout= gid= group_id= kernel_cache max_read= negative_timeout= noauto noforget remember= remount rootmode= uid= umask= user user_id= versions"
complete -c borg -f -s o                            -d 'Fuse mount OPTION' -a "$fuse_options"       -n "__fish_seen_subcommand_from mount"
# Archive filters
complete -c borg -f -s P -l 'prefix'                -d 'Only archive names starting with PREFIX'    -n "__fish_seen_subcommand_from mount"
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from mount"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from mount"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from mount"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from mount"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from mount"
complete -c borg -f      -l 'strip-components'      -d 'Remove NUMBER of leading path elements'     -n "__fish_seen_subcommand_from mount"

# borg umount
# no specific options

# borg tag options
complete -c borg -f      -l 'set'                   -d 'Set tags (can be given multiple times)'      -n "__fish_seen_subcommand_from tag"
complete -c borg -f      -l 'add'                   -d 'Add tags (can be given multiple times)'      -n "__fish_seen_subcommand_from tag"
complete -c borg -f      -l 'remove'                -d 'Remove tags (can be given multiple times)'   -n "__fish_seen_subcommand_from tag"
# Archive filters
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from tag"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from tag"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from tag"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from tag"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from tag"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from tag"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from tag"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from tag"

# borg key change-passphrase
# no specific options

# borg key export
complete -c borg -f      -l 'paper'                 -d 'Create an export for printing'              -n "__fish_seen_subcommand_from export"
complete -c borg -f      -l 'qr-html'               -d 'Create an html file for printing and qr'    -n "__fish_seen_subcommand_from export"

# borg transfer options
complete -c borg -f -s n -l 'dry-run'               -d 'Do not change repository, just check'       -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'other-repo'            -d 'Transfer archives from the other repository' -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'from-borg1'            -d 'Other repository is borg 1.x'               -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'upgrader'              -d 'Use the upgrader to convert transferred data' -n "__fish_seen_subcommand_from transfer"
complete -c borg -f -s C -l 'compression'           -d 'Select compression algorithm' -a "$compression_methods" -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'recompress'            -d 'Recompress chunks CONDITION' -a "$recompress_when" -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'chunker-params'        -d 'Chunker PARAMETERS [19,23,21,4095]'         -n "__fish_seen_subcommand_from transfer"
# Archive filters
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from transfer"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from transfer"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from transfer"

# borg key import
complete -c borg -f      -l 'paper'                 -d 'Import from a backup done with --paper'     -n "__fish_seen_subcommand_from import"

# borg undelete options
complete -c borg -f -s n -l 'dry-run'               -d 'Do not change repository'                   -n "__fish_seen_subcommand_from undelete"
complete -c borg -f      -l 'list'                  -d 'Output verbose list of archives'            -n "__fish_seen_subcommand_from undelete"
# Archive filters
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from undelete"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from undelete"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from undelete"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from undelete"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from undelete"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from undelete"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from undelete"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from undelete"


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
# Archive filters
complete -c borg -f -s a -l 'match-archives'        -d 'Only consider archives matching all patterns' -n "__fish_seen_subcommand_from recreate"
set -l sort_keys "timestamp archive name id tags host user"
complete -c borg -f      -l 'sort-by'               -d 'Sorting KEYS [timestamp]' -a "$sort_keys"   -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'first'                 -d 'Only first N archives'                      -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'last'                  -d 'Only last N archives'                       -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'oldest'                -d 'Consider archives within TIMESPAN from oldest' -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'newest'                -d 'Consider archives within TIMESPAN from newest' -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'older'                 -d 'Consider archives older than TIMESPAN'      -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'newer'                 -d 'Consider archives newer than TIMESPAN'      -n "__fish_seen_subcommand_from recreate"
# Archive options
complete -c borg -f      -l 'target'                -d "Create a new ARCHIVE"                       -n "__fish_seen_subcommand_from recreate"
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
complete -c borg -f      -l 'tar-format'            -d 'Select tar format: BORG, PAX or GNU'        -n "__fish_seen_subcommand_from export-tar"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from export-tar"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from export-tar"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from export-tar"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from export-tar"
complete -c borg -f      -l 'strip-components'      -d 'Remove NUMBER of leading path elements'     -n "__fish_seen_subcommand_from export-tar"

# borg import-tar options
complete -c borg         -l 'tar-filter'            -d 'Filter program to pipe data through'        -n "__fish_seen_subcommand_from import-tar"
complete -c borg -f -s s -l 'stats'                 -d 'Print statistics for the created archive'   -n "__fish_seen_subcommand_from import-tar"
complete -c borg -f      -l 'list'                  -d 'Print verbose list of items'                -n "__fish_seen_subcommand_from import-tar"
complete -c borg -f      -l 'filter'                -d 'Only display items with given STATUSCHARS'  -n "__fish_seen_subcommand_from import-tar"
complete -c borg -f      -l 'json'                  -d 'Output stats as JSON'                       -n "__fish_seen_subcommand_from import-tar"
complete -c borg -f      -l 'ignore-zeros'          -d 'Ignore zero-filled blocks in the input'     -n "__fish_seen_subcommand_from import-tar"
complete -c borg -f      -l 'comment'               -d 'Add COMMENT to the archive'                 -n "__fish_seen_subcommand_from import-tar"
complete -c borg -f      -l 'timestamp'             -d 'Set creation TIME (yyyy-mm-ddThh:mm:ss)'    -n "__fish_seen_subcommand_from import-tar"
complete -c borg -f      -l 'chunker-params'        -d 'Chunker PARAMETERS [19,23,21,4095]'         -n "__fish_seen_subcommand_from import-tar"
complete -c borg -f -s C -l 'compression'           -d 'Select compression ALGORITHM,LEVEL [lz4]' -a "$compression_methods" -n "__fish_seen_subcommand_from import-tar"
# Exclusion options
complete -c borg    -s e -l 'exclude'               -d 'Exclude paths matching PATTERN'             -n "__fish_seen_subcommand_from recreate"
complete -c borg         -l 'exclude-from'          -d 'Read exclude patterns from EXCLUDEFILE'     -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'pattern'               -d 'Include/exclude paths matching PATTERN'     -n "__fish_seen_subcommand_from recreate"
complete -c borg         -l 'patterns-from'         -d 'Include/exclude paths from PATTERNFILE'     -n "__fish_seen_subcommand_from recreate"
complete -c borg -f      -l 'strip-components'      -d 'Remove NUMBER of leading path elements'     -n "__fish_seen_subcommand_from recreate"

# borg serve
complete -c borg         -l 'restrict-to-path'      -d 'Restrict repository access to PATH'         -n "__fish_seen_subcommand_from serve"
complete -c borg         -l 'restrict-to-repository' -d 'Restrict repository access at PATH'        -n "__fish_seen_subcommand_from serve"


# borg with-lock
# no specific options

# borg break-lock
# no specific options

# borg benchmark
# no specific options

# borg help
# no specific options


function __fish_borg_archives
    # additionally to aid:XXXXXXXX we show archive (series) name and timestamp
    borg repo-list --format="aid:{id:.8}{TAB}{archive} {start}{NEWLINE}" 2>/dev/null
end

function __fish_borg_archive_arg --description 'Test if current command is a specific borg command with token count' --argument command token_count
    # Check if we're in the context of a specific borg command
    set -l tokens (commandline --tokenize)
    set -l cmdline (commandline --current-process)

    # Make sure we're in a borg command context
    if not test $tokens[1] = "borg"
        return 1
    end

    # Make sure we're in the specific command context
    if not test $tokens[2] = "$command"
        return 1
    end

    # Check if we're at the right token position
    if not test (count $tokens) "-eq" "$token_count"
        return 1
    end

    # Additional check to ensure we're not in the middle of typing an option
    if string match --quiet --regex -- "^-" (commandline --current-token)
        return 1
    end

    return 0
end

# The following completions use the -F flag to force disable filename completion
# for various borg commands, ensuring only archive names are suggested.
# We also use the -e flag to explicitly erase all default completions before adding our custom ones.

# Global rules to disable filename completions for specific borg commands
# This ensures that no filename completions are shown for these commands
complete -c borg -e -n '__fish_seen_subcommand_from diff delete list info extract mount export-tar rename tag undelete recreate transfer check analyze'

# First, explicitly erase all default completions for each command
# This is the most specific rule and should take precedence
complete -c borg -e -n '__fish_borg_archive_arg "diff" 2'
complete -c borg -e -n '__fish_borg_archive_arg "diff" 3'
complete -c borg -e -n '__fish_borg_archive_arg "delete" 2'
complete -c borg -e -n '__fish_borg_archive_arg "list" 2'
complete -c borg -e -n '__fish_borg_archive_arg "info" 2'
complete -c borg -e -n '__fish_borg_archive_arg "extract" 2'
complete -c borg -e -n '__fish_borg_archive_arg "mount" 2'
complete -c borg -e -n '__fish_borg_archive_arg "export-tar" 2'
complete -c borg -e -n '__fish_borg_archive_arg "rename" 2'
complete -c borg -e -n '__fish_borg_archive_arg "tag" 2'
complete -c borg -e -n '__fish_borg_archive_arg "undelete" 2'
complete -c borg -e -n '__fish_borg_archive_arg "recreate" 2'
complete -c borg -e -n '__fish_borg_archive_arg "transfer" 2'
complete -c borg -e -n '__fish_borg_archive_arg "check" 2'
complete -c borg -e -n '__fish_borg_archive_arg "analyze" 2'

# Also add specific rules to disable filename completions at the exact position
# This ensures that no filename completions are shown at the position where we expect archive names
complete -c borg --no-files -n '__fish_borg_archive_arg "diff" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "diff" 3'
complete -c borg --no-files -n '__fish_borg_archive_arg "delete" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "list" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "info" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "extract" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "mount" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "export-tar" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "rename" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "tag" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "undelete" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "recreate" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "transfer" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "check" 2'
complete -c borg --no-files -n '__fish_borg_archive_arg "analyze" 2'

# Then add our custom completions with high priority and no-files
# This ensures no filename completions are shown and our custom completions take precedence
complete -c borg -p 100 -n '__fish_borg_archive_arg "diff" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "diff" 3' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "delete" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "list" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "info" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "extract" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "mount" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "export-tar" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "rename" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "tag" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "undelete" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "recreate" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "transfer" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "check" 2' -a '(__fish_borg_archives)' --no-files
complete -c borg -p 100 -n '__fish_borg_archive_arg "analyze" 2' -a '(__fish_borg_archives)' --no-files
