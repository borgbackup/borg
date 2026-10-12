.. include:: known-repos.rst.inc

Examples
~~~~~~~~
::

    $ borg known-repos
    Repository ID     Layout Cache Security           Key files Last written        Location
    401606173d54eab.. borg2  180 B aes256-ocb, sha256 -         2026-10-12T17:15:19 /path/to/repo

    $ borg known-repos --json
    {
        "repositories": [
            {
                "cache_config_mtime": "2026-10-12T17:15:19.785785+09:00",
                "cache_size": 180,
                "has_cache": true,
                "has_security_info": true,
                "id": "401606173d54eab22cd98de67278d093e3bae7b187da3af8c6430f18fa1112bb",
                "key_file_count": 0,
                "key_type": "aes256-ocb, sha256",
                "layout": "borg2",
                "location": "/path/to/repo",
                "location_mismatch": false
            }
        ]
    }
