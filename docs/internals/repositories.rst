All About Repositories: Handling Protocols
==========================================

A repository is where borg keeps all its backup data. It abstracts the details of
repositories in order to support multiple remote locations behind a similar interface.

The top-level abstraction is the Repository class which then loads the
appropriate specific repository class for the location specified by the user.

For example, a ``file://`` location will end up loading a ``LocalRepository`` while
an ``ssh://`` location will end up loading a ``RemoteRepository`` (which communicates
with a remote borg instance over ssh).

Adding A New Repository Backend
-------------------------------

You can see most of what needs to be done by looking at the main ``Repository``
class in ``repository.py``. Every call it gets, it proxies to a subclass that
does the real work. That is what you'll write.

A few of the methods are optional and can return ``None`` or do nothing:

- ``get_free_nonce``
- ``commit_nonce_reservation``
- ``config`` (if remote)
- ``save_config()`` (if remote)

Write your new repository class in a file in the ``repositories`` directory.

After writing your new class, add support for it in the ``Repository.__init__``
method, which inspects a location's protocol and instantiates the appropriate
backend.
