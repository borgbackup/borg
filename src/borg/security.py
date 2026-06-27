import shutil
from pathlib import Path

from .helpers import Error
from .helpers import get_security_dir
from .helpers import yes
from .platform import SaveFile

from .logger import create_logger

logger = create_logger()


def _security_dir(repository, *, create=True):
    """Security dir path for repository, using the borg 1.x layout for v1 repos."""
    if repository.version == 1:
        from .legacy.fs import get_security_dir as get_security_dir_legacy

        return get_security_dir_legacy(repository.id_str, create=create)
    return get_security_dir(repository.id_str, create=create)


class CacheInitAbortedError(Error):
    """Cache initialization aborted"""

    exit_mcode = 60


class EncryptionMethodMismatch(Error):
    """Repository encryption method changed since last access, refusing to continue"""

    exit_mcode = 61


class RepositoryAccessAborted(Error):
    """Repository access aborted"""

    exit_mcode = 62


class RepositoryIDNotUnique(Error):
    """Cache is newer than repository - do you have multiple, independently updated repos with same ID?"""

    exit_mcode = 63


class RepositoryReplay(Error):
    """Cache, or information obtained from the security directory is newer than repository - this is either an attack or unsafe (multiple repos with same ID)"""

    exit_mcode = 64


class SecurityManager:
    """
    Tracks repositories. Ensures that nothing bad happens (repository swaps,
    replay attacks, unknown repositories, etc.).

    This is complicated by the cache being initially used for this, while
    only some commands actually use the cache, which meant that other commands
    did not perform these checks.

    Further complications were created by the cache being a cache, so it
    could be legitimately deleted, which is annoying because Borg did not
    recognize repositories after that.

    Therefore, a second location, the security database (see get_security_dir),
    was introduced, which stores this information. However, this means that
    the code has to deal with a cache existing but no security database entry,
    or inconsistencies between the security database and the cache which have to
    be reconciled, and also with no cache existing but a security database entry.
    """

    def __init__(self, repository):
        self.repository = repository
        self.dir = Path(_security_dir(repository))
        self.key_type_file = self.dir / "key-type"
        self.location_file = self.dir / "location"
        self.manifest_ts_file = self.dir / "manifest-timestamp"

    @staticmethod
    def destroy(repository, path=None):
        """Destroys the security directory for ``repository`` or at ``path``."""
        path = path or _security_dir(repository)
        if Path(path).exists():
            shutil.rmtree(path)

    def known(self):
        return all(f.exists() for f in (self.key_type_file, self.location_file, self.manifest_ts_file))

    def key_matches(self, key):
        if not self.known():
            return False
        try:
            with self.key_type_file.open() as fd:
                type = fd.read()
                return type == str(key.TYPE)
        except OSError as exc:
            logger.warning("Could not read/parse key type file: %s", exc)

    def save(self, manifest, key):
        logger.debug("security: saving state for %s to %s", self.repository.id_str, str(self.dir))
        current_location = self.repository._location.canonical_path()
        logger.debug("security: current location   %s", current_location)
        logger.debug("security: key type           %s", str(key.TYPE))
        logger.debug("security: manifest timestamp %s", manifest.timestamp)
        with SaveFile(self.location_file) as fd:
            fd.write(current_location)
        with SaveFile(self.key_type_file) as fd:
            fd.write(str(key.TYPE))
        with SaveFile(self.manifest_ts_file) as fd:
            fd.write(manifest.timestamp)

    def assert_location_matches(self):
        # Warn user before sending data to a relocated repository
        try:
            with self.location_file.open() as fd:
                previous_location = fd.read()
            logger.debug("security: read previous location %r", previous_location)
        except FileNotFoundError:
            logger.debug("security: previous location file %s not found", self.location_file)
            previous_location = None
        except OSError as exc:
            logger.warning("Could not read previous location file: %s", exc)
            previous_location = None

        repository_location = self.repository._location.canonical_path()
        if previous_location and previous_location != repository_location:
            msg = (
                "Warning: The repository at location {} was previously located at {}\n".format(
                    repository_location, previous_location
                )
                + "Do you want to continue? [yN] "
            )
            if not yes(
                msg,
                false_msg="Aborting.",
                invalid_msg="Invalid answer, aborting.",
                retry=False,
                env_var_override="BORG_RELOCATED_REPO_ACCESS_IS_OK",
            ):
                raise RepositoryAccessAborted()
            # adapt on-disk config immediately if the new location was accepted
            logger.debug("security: updating location stored in security dir")
            with SaveFile(self.location_file) as fd:
                fd.write(repository_location)

    def assert_no_manifest_replay(self, manifest, key):
        from .crypto.key import PlaintextKey

        try:
            with self.manifest_ts_file.open() as fd:
                timestamp = fd.read()
            logger.debug("security: read manifest timestamp %r", timestamp)
        except FileNotFoundError:
            logger.debug("security: manifest timestamp file %s not found", self.manifest_ts_file)
            timestamp = ""
        except OSError as exc:
            logger.warning("Could not read previous location file: %s", exc)
            timestamp = ""
        logger.debug("security: determined newest manifest timestamp as %s", timestamp)
        # If repository is older than the cache or security dir something fishy is going on
        if timestamp and timestamp > manifest.timestamp:
            if isinstance(key, PlaintextKey):
                raise RepositoryIDNotUnique()
            else:
                raise RepositoryReplay()

    def assert_key_type(self, key):
        # Make sure an encrypted repository has not been swapped for an unencrypted repository
        if self.known() and not self.key_matches(key):
            raise EncryptionMethodMismatch()

    def assert_secure(self, manifest, key, *, warn_if_unencrypted=True):
        # warn_if_unencrypted=False is only used for initializing a new repository.
        # Thus, avoiding asking about a repository that's currently initializing.
        self.assert_access_unknown(warn_if_unencrypted, manifest, key)
        self._assert_secure(manifest, key)
        logger.debug("security: repository checks ok, allowing access")

    def _assert_secure(self, manifest, key):
        self.assert_location_matches()
        self.assert_key_type(key)
        self.assert_no_manifest_replay(manifest, key)
        if not self.known():
            logger.debug("security: remembering previously unknown repository")
            self.save(manifest, key)

    def assert_access_unknown(self, warn_if_unencrypted, manifest, key):
        # warn_if_unencrypted=False is only used for initializing a new repository.
        # Thus, avoiding asking about a repository that's currently initializing.
        if not key.logically_encrypted and not self.known():
            msg = (
                "Warning: Attempting to access a previously unknown unencrypted repository!\n"
                + "Do you want to continue? [yN] "
            )
            allow_access = not warn_if_unencrypted or yes(
                msg,
                false_msg="Aborting.",
                invalid_msg="Invalid answer, aborting.",
                retry=False,
                env_var_override="BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK",
            )
            if allow_access:
                if warn_if_unencrypted:
                    logger.debug("security: remembering unknown unencrypted repository (explicitly allowed)")
                else:
                    logger.debug("security: initializing unencrypted repository")
                self.save(manifest, key)
            else:
                raise CacheInitAbortedError()


def assert_secure(repository, manifest):
    sm = SecurityManager(repository)
    sm.assert_secure(manifest, manifest.key)
