.. include:: config.rst.inc

.. note::

   The repository & cache config files are some of the only directly manipulable
   parts of a repository that aren't versioned or backed up, so be careful when
   making changes\!

Examples
~~~~~~~~
::

    # find cache directory
    $ cd ~/.cache/borg/$(borg config /path/to/repo id)

    # reserve some space
    $ borg config /path/to/repo additional_free_space 2G

    # make a repo append-only
    $ borg config /path/to/repo append_only 1


