.. include:: known-repos.rst.inc

Examples
~~~~~~~~
::

    $ borg known-repos
    Repository ID: 0a2744f216526be75ae14a5fa5b123127bb218558219f6203e09e4f220e45903
      Layout: borg2
      Location: /path/to/repo
      Local cache: yes, 1.23 MB
      Cache last written: 2026-10-07T21:00:00.000000+09:00
      Security info: yes (aes256-ocb, sha256)

    $ borg known-repos --json
    {
        "repositories": [
            {
                "cache_config_mtime": "2026-10-07T21:00:00.000000+09:00",
                "cache_size": 1234567,
                "has_cache": true,
                "has_security_info": true,
                "id": "0a2744f216526be75ae14a5fa5b123127bb218558219f6203e09e4f220e45903",
                "key_type": "aes256-ocb, sha256",
                "key_type_raw": "16",
                "layout": "borg2",
                "location": "/path/to/repo"
            }
        ]
    }
