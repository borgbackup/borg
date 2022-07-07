import getpass
import os
import shlex
import subprocess
import sys

from . import bin_to_hex
from . import Error
from . import yes
from . import prepare_subprocess_env

from ..logger import create_logger

logger = create_logger()


class NoPassphraseFailure(Error):
    """can not acquire a passphrase: {}"""


class PassphraseWrong(Error):
    """passphrase supplied in BORG_PASSPHRASE, by BORG_PASSCOMMAND or via BORG_PASSPHRASE_FD is incorrect."""


class PasscommandFailure(Error):
    """passcommand supplied in BORG_PASSCOMMAND failed: {}"""


class PasswordRetriesExceeded(Error):
    """exceeded the maximum password retries"""


class Passphrase(str):
    @classmethod
    def _env_passphrase(cls, env_var, default=None):
        passphrase = os.environ.get(env_var, default)
        if passphrase is not None:
            return cls(passphrase)

    @classmethod
    def env_passphrase(cls, default=None):
        passphrase = cls._env_passphrase("BORG_PASSPHRASE", default)
        if passphrase is not None:
            return passphrase
        passphrase = cls.env_passcommand()
        if passphrase is not None:
            return passphrase
        passphrase = cls.fd_passphrase()
        if passphrase is not None:
            return passphrase

    @classmethod
    def env_passcommand(cls, default=None):
        passcommand = os.environ.get("BORG_PASSCOMMAND", None)
        if passcommand is not None:
            # passcommand is a system command (not inside pyinstaller env)
            env = prepare_subprocess_env(system=True)
            try:
                passphrase = subprocess.check_output(shlex.split(passcommand), universal_newlines=True, env=env)
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                raise PasscommandFailure(e)
            return cls(passphrase.rstrip("\n"))

    @classmethod
    def fd_passphrase(cls):
        try:
            fd = int(os.environ.get("BORG_PASSPHRASE_FD"))
        except (ValueError, TypeError):
            return None
        with os.fdopen(fd, mode="r") as f:
            passphrase = f.read()
        return cls(passphrase.rstrip("\n"))

    @classmethod
    def env_new_passphrase(cls, default=None):
        return cls._env_passphrase("BORG_NEW_PASSPHRASE", default)

    @classmethod
    def getpass(cls, prompt):
        try:
            pw = getpass.getpass(prompt)
        except EOFError:
            if prompt:
                print()  # avoid err msg appearing right of prompt
            msg = []
            for env_var in "BORG_PASSPHRASE", "BORG_PASSCOMMAND":
                env_var_set = os.environ.get(env_var) is not None
                msg.append("{} is {}.".format(env_var, "set" if env_var_set else "not set"))
            msg.append("Interactive password query failed.")
            raise NoPassphraseFailure(" ".join(msg)) from None
        else:
            return cls(pw)

    @classmethod
    def verification(cls, passphrase):
        msg = "Do you want your passphrase to be displayed for verification? [yN]: "
        if yes(
            msg,
            retry_msg=msg,
            invalid_msg="Invalid answer, try again.",
            retry=True,
            env_var_override="BORG_DISPLAY_PASSPHRASE",
        ):
            print('Your passphrase (between double-quotes): "%s"' % passphrase, file=sys.stderr)
            print("Make sure the passphrase displayed above is exactly what you wanted.", file=sys.stderr)
            try:
                passphrase.encode("ascii")
            except UnicodeEncodeError:
                print(
                    "Your passphrase (UTF-8 encoding in hex): %s" % bin_to_hex(passphrase.encode("utf-8")),
                    file=sys.stderr,
                )
                print(
                    "As you have a non-ASCII passphrase, it is recommended to keep the "
                    "UTF-8 encoding in hex together with the passphrase at a safe place.",
                    file=sys.stderr,
                )

    @classmethod
    def new(cls, allow_empty=False):
        passphrase = cls.env_new_passphrase()
        if passphrase is not None:
            return passphrase
        passphrase = cls.env_passphrase()
        if passphrase is not None:
            return passphrase
        for retry in range(1, 11):
            passphrase = cls.getpass("Enter new passphrase: ")
            if allow_empty or passphrase:
                passphrase2 = cls.getpass("Enter same passphrase again: ")
                if passphrase == passphrase2:
                    cls.verification(passphrase)
                    logger.info("Remember your passphrase. Your data will be inaccessible without it.")
                    return passphrase
                else:
                    print("Passphrases do not match", file=sys.stderr)
            else:
                print("Passphrase must not be blank", file=sys.stderr)
        else:
            raise PasswordRetriesExceeded

    def __repr__(self):
        return '<Passphrase "***hidden***">'
