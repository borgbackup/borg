# borgbackup - main setup code (extension building here, rest see pyproject.toml)

import os
import re
import sys
import warnings
from collections import defaultdict

try:
    import multiprocessing
except ImportError:
    multiprocessing = None

from setuptools.command.build_ext import build_ext
from setuptools import setup, Extension
from setuptools.command.sdist import sdist

try:
    from Cython.Build import cythonize

    cythonize_import_error_msg = None
except ImportError as exc:
    # either there is no Cython installed or there is some issue with it.
    cythonize = None
    cythonize_import_error_msg = "ImportError: " + str(exc)
    if "failed to map segment from shared object" in cythonize_import_error_msg:
        cythonize_import_error_msg += " Check if the borg build uses a +exec filesystem."

sys.path += [os.path.dirname(__file__)]

is_win32 = sys.platform.startswith("win32")
is_openbsd = sys.platform.startswith("openbsd")

# Number of threads to use for cythonize, not used on Windows
cpu_threads = multiprocessing.cpu_count() if multiprocessing and multiprocessing.get_start_method() != "spawn" else None

# How the build process finds the system libs:
#
# 1. if BORG_{LIBXXX,OPENSSL}_PREFIX is set, it will use headers and libs from there.
# 2. if not and pkg-config can locate the lib, the lib located by
#    pkg-config will be used. We use the pkg-config tool via the pkgconfig
#    python package, which must be installed before invoking setup.py.
#    if pkgconfig is not installed, this step is skipped.
# 3. otherwise raise a fatal error.

# Are we building on ReadTheDocs?
on_rtd = os.environ.get("READTHEDOCS")


def check_version_detectable():
    """Fail before building anything if the borg version can not be determined.

    The version is computed from git tags by setuptools_scm. In a shallow clone or a clone
    without tags this does not fail, it just yields a wrong version like 0.1.dev1+gedcff4f -
    and that is only noticed after cythonizing and compiling everything, see #7259.

    We ask setuptools_scm itself instead of reimplementing its tag lookup here.
    """
    if on_rtd:
        return  # building the docs does not need an exact version.
    try:
        from setuptools_scm import get_version
    except ImportError:
        return  # can not check. if the version is really needed, setup() will complain later.

    here = os.path.dirname(os.path.abspath(__file__))
    found_tags = []

    def capture_tag(scm_version):
        # a custom version_scheme is only used to get at the tag setuptools_scm found,
        # the version we return here is not used for anything.
        found_tags.append(str(scm_version.tag))
        return "0"

    def fail(reason):
        raise SystemExit(
            "Can not determine the borg version: %s\n"
            "\n"
            "The version is computed from git tags, so building here would silently produce a\n"
            "wrong version (like 0.1.dev1+gedcff4f). Use one of these:\n"
            "\n"
            "- clone the full repository (a shallow clone or a clone without tags will not work):\n"
            "      git clone https://github.com/borgbackup/borg.git\n"
            "- fetch what your existing clone is missing:\n"
            "      git fetch --unshallow --tags\n"
            "- or give the version explicitly, e.g. when building without git:\n"
            "      SETUPTOOLS_SCM_PRETEND_VERSION=2.0.0b23 pip install -e ." % reason
        )

    def ask_setuptools_scm(**extra):
        del found_tags[:]
        with warnings.catch_warnings():
            # the real build triggers the same warnings, we do not want to duplicate them.
            warnings.simplefilter("ignore")
            # raises LookupError (with its own helpful message) if there is no version source at all.
            get_version(root=here, version_scheme=capture_tag, local_scheme=lambda scm_version: "", **extra)

    try:
        # let setuptools_scm fail on a shallow repository instead of computing a version from
        # truncated history, see
        # https://setuptools-scm.readthedocs.io/en/latest/integrations/#enforce-fail-on-shallow-repositories
        # This is not in pyproject.toml on purpose: the "scm" table only exists in recent
        # setuptools-scm and older ones hard-fail on unknown keys there, see #10193.
        ask_setuptools_scm(scm={"git": {"pre_parse": "fail_on_shallow"}})
    except TypeError:  # setuptools-scm too old for the "scm" config, check what we can without it.
        ask_setuptools_scm()
    except ValueError as err:  # that is how fail_on_shallow complains.
        fail(str(err).splitlines()[0])

    if not found_tags:
        # no tag was looked at: the version came from SETUPTOOLS_SCM_PRETEND_VERSION or, when
        # building from a sdist, from PKG-INFO. Nothing to check in that case.
        return
    if found_tags[0].startswith("0."):
        # borg has no 0.x releases, so this is the fallback tag setuptools_scm uses when it does
        # not find any tag at all. Note: a full clone without tags is not shallow, so
        # fail_on_shallow does not catch this one.
        fail("setuptools_scm did not find a borg release tag.")


check_version_detectable()

# Extra cflags for all extensions, usually just warnings we want to enable explicitly
cflags = ["-Wall", "-Wextra", "-Wpointer-arith"]

if not is_win32:
    cflags.extend(["-Wstrict-prototypes"])

compress_source = "src/borg/compress.pyx"
crypto_ll_source = "src/borg/crypto/low_level.pyx"
crypto_legacy_ll_source = "src/borg/legacy/crypto/low_level.pyx"
chunker_base_source = "src/borg/chunkers/base.pyx"
buzhash_source = "src/borg/chunkers/buzhash.pyx"
buzhash64_source = "src/borg/chunkers/buzhash64.pyx"
buzhash64_impl_source = "src/borg/chunkers/buzhash64_impl.c"
fastcdc_source = "src/borg/chunkers/fastcdc.pyx"
fastcdc_impl_source = "src/borg/chunkers/fastcdc_impl.c"
rabin_aes_source = "src/borg/chunkers/rabin_aes.pyx"
rabin_aes_impl_source = "src/borg/chunkers/rabin_aes_impl.c"
goldilocks_aes_source = "src/borg/chunkers/goldilocks_aes.pyx"
goldilocks_aes_impl_source = "src/borg/chunkers/goldilocks_aes_impl.c"
phte_chunker_source = "src/borg/chunkers/phte_chunker.pyx"
toeplitz_aes_source = "src/borg/chunkers/toeplitz_aes.pyx"
toeplitz_aes_impl_source = "src/borg/chunkers/toeplitz_aes_impl.c"
reader_source = "src/borg/chunkers/reader.pyx"
hashindex_source = "src/borg/hashindex.pyx"
item_source = "src/borg/item.pyx"
platform_posix_source = "src/borg/platform/posix.pyx"
platform_linux_source = "src/borg/platform/linux.pyx"
platform_syncfilerange_source = "src/borg/platform/syncfilerange.pyx"
platform_darwin_source = "src/borg/platform/darwin.pyx"
platform_freebsd_source = "src/borg/platform/freebsd.pyx"
platform_netbsd_source = "src/borg/platform/netbsd.pyx"
platform_windows_source = "src/borg/platform/windows.pyx"

cython_sources = [
    compress_source,
    crypto_ll_source,
    crypto_legacy_ll_source,
    chunker_base_source,
    buzhash_source,
    buzhash64_source,
    fastcdc_source,
    phte_chunker_source,
    rabin_aes_source,
    goldilocks_aes_source,
    toeplitz_aes_source,
    reader_source,
    hashindex_source,
    item_source,
    platform_posix_source,
    platform_linux_source,
    platform_syncfilerange_source,
    platform_freebsd_source,
    platform_netbsd_source,
    platform_darwin_source,
    platform_windows_source,
]

if cythonize:
    Sdist = sdist
else:

    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            raise Exception("Cython is required to run sdist")

    cython_c_files = [fn.replace(".pyx", ".c") for fn in cython_sources]
    if not on_rtd and not all(os.path.exists(path) for path in cython_c_files):
        raise ImportError(
            "The Git version of Borg needs a working Cython. "
            + "Install or fix Cython or use a released Borg version. "
            + "Importing cythonize failed with: "
            + cythonize_import_error_msg
        )


cmdclass = {"build_ext": build_ext, "sdist": Sdist}


ext_modules = []
if not on_rtd:

    def members_appended(*ds):
        result = defaultdict(list)
        for d in ds:
            for k, v in d.items():
                assert isinstance(v, list)
                result[k].extend(v)
        return result

    try:
        import pkgconfig as pc
    except ImportError:
        print("Warning: cannot import pkgconfig Python package.")
        pc = None

    def lib_ext_kwargs(pc, prefix_env_var, lib_name, lib_pkg_name, pc_version, lib_subdir="lib"):
        system_prefix = os.environ.get(prefix_env_var)
        if system_prefix:
            print(f"Detected and preferring {lib_pkg_name} [via {prefix_env_var}]")
            return dict(
                include_dirs=[os.path.join(system_prefix, "include")],
                library_dirs=[os.path.join(system_prefix, lib_subdir)],
                libraries=[lib_name],
            )

        if pc and pc.installed(lib_pkg_name, pc_version):
            print(f"Detected and preferring {lib_pkg_name} [via pkg-config]")
            return pc.parse(lib_pkg_name)
        raise Exception(
            f"Could not find {lib_name} lib/headers, please set {prefix_env_var} "
            f"or ensure {lib_pkg_name}.pc is in PKG_CONFIG_PATH."
        )

    if is_win32:
        crypto_ext_lib = lib_ext_kwargs(pc, "BORG_OPENSSL_PREFIX", "libcrypto", "libcrypto", ">=3.2.0", lib_subdir="")
    elif is_openbsd:
        # Use OpenSSL (not LibreSSL) because we need AES-OCB via the EVP API. Link
        # it statically to avoid conflicting with shared libcrypto from the base
        # OS pulled in via dependencies.
        openssl_prefix = os.environ.get("BORG_OPENSSL_PREFIX", "/usr/local")
        openssl_name = os.environ.get("BORG_OPENSSL_NAME", "eopenssl35")
        crypto_ext_lib = dict(
            include_dirs=[os.path.join(openssl_prefix, "include", openssl_name)],
            extra_objects=[os.path.join(openssl_prefix, "lib", openssl_name, "libcrypto.a")],
        )
    else:
        crypto_ext_lib = lib_ext_kwargs(pc, "BORG_OPENSSL_PREFIX", "crypto", "libcrypto", ">=3.2.0")

    crypto_ext_kwargs = members_appended(
        dict(sources=[crypto_ll_source]), crypto_ext_lib, dict(extra_compile_args=cflags)
    )

    crypto_legacy_ext_kwargs = members_appended(
        dict(sources=[crypto_legacy_ll_source]), crypto_ext_lib, dict(extra_compile_args=cflags)
    )

    # rabin-aes uses OpenSSL (EVP AES-128-ECB) in its C scan kernel
    rabin_aes_ext_kwargs = members_appended(
        dict(sources=[rabin_aes_source, rabin_aes_impl_source], include_dirs=["src/borg/chunkers"]),
        crypto_ext_lib,
        dict(extra_compile_args=cflags),
    )

    # goldilocks-aes likewise (same PRF layer, different rolling hash)
    goldilocks_aes_ext_kwargs = members_appended(
        dict(sources=[goldilocks_aes_source, goldilocks_aes_impl_source], include_dirs=["src/borg/chunkers"]),
        crypto_ext_lib,
        dict(extra_compile_args=cflags),
    )

    # toeplitz-aes likewise (same PRF layer, different rolling hash)
    toeplitz_aes_ext_kwargs = members_appended(
        dict(sources=[toeplitz_aes_source, toeplitz_aes_impl_source], include_dirs=["src/borg/chunkers"]),
        crypto_ext_lib,
        dict(extra_compile_args=cflags),
    )

    compress_ext_kwargs = members_appended(
        dict(sources=[compress_source]),
        lib_ext_kwargs(pc, "BORG_LIBLZ4_PREFIX", "lz4", "liblz4", ">= 1.7.0"),
        dict(extra_compile_args=cflags),
    )

    if sys.platform == "linux":
        linux_ext_kwargs = members_appended(
            dict(sources=[platform_linux_source]),
            lib_ext_kwargs(pc, "BORG_LIBACL_PREFIX", "acl", "libacl", ">= 2.2.47"),
            dict(extra_compile_args=cflags),
        )
    else:
        linux_ext_kwargs = members_appended(
            dict(sources=[platform_linux_source], libraries=["acl"], extra_compile_args=cflags)
        )

    ext_modules += [
        Extension("borg.crypto.low_level", **crypto_ext_kwargs),
        Extension("borg.legacy.crypto.low_level", **crypto_legacy_ext_kwargs),
        Extension("borg.compress", **compress_ext_kwargs),
        Extension("borg.hashindex", [hashindex_source], extra_compile_args=cflags),
        Extension("borg.item", [item_source], extra_compile_args=cflags),
        Extension("borg.chunkers.base", [chunker_base_source], extra_compile_args=cflags),
        Extension("borg.chunkers.buzhash", [buzhash_source], extra_compile_args=cflags),
        Extension(
            "borg.chunkers.buzhash64",
            [buzhash64_source, buzhash64_impl_source],
            include_dirs=["src/borg/chunkers"],
            extra_compile_args=cflags,
        ),
        Extension(
            "borg.chunkers.fastcdc",
            [fastcdc_source, fastcdc_impl_source],
            include_dirs=["src/borg/chunkers"],
            extra_compile_args=cflags,
        ),
        Extension("borg.chunkers.phte_chunker", [phte_chunker_source], extra_compile_args=cflags),
        Extension("borg.chunkers.rabin_aes", **rabin_aes_ext_kwargs),
        Extension("borg.chunkers.goldilocks_aes", **goldilocks_aes_ext_kwargs),
        Extension("borg.chunkers.toeplitz_aes", **toeplitz_aes_ext_kwargs),
        Extension("borg.chunkers.reader", [reader_source], extra_compile_args=cflags),
    ]

    posix_ext = Extension("borg.platform.posix", [platform_posix_source], extra_compile_args=cflags)
    linux_ext = Extension("borg.platform.linux", **linux_ext_kwargs)

    syncfilerange_ext = Extension(
        "borg.platform.syncfilerange", [platform_syncfilerange_source], extra_compile_args=cflags
    )
    freebsd_ext = Extension("borg.platform.freebsd", [platform_freebsd_source], extra_compile_args=cflags)
    netbsd_ext = Extension("borg.platform.netbsd", [platform_netbsd_source], extra_compile_args=cflags)
    darwin_ext = Extension("borg.platform.darwin", [platform_darwin_source], extra_compile_args=cflags)
    windows_ext = Extension("borg.platform.windows", [platform_windows_source], extra_compile_args=cflags)

    if not is_win32:
        ext_modules.append(posix_ext)
    else:
        ext_modules.append(windows_ext)
    if sys.platform == "linux":
        ext_modules.append(linux_ext)
        ext_modules.append(syncfilerange_ext)
    elif sys.platform.startswith("freebsd"):
        ext_modules.append(freebsd_ext)
    elif sys.platform.startswith("netbsd"):
        ext_modules.append(netbsd_ext)
    elif sys.platform == "darwin":
        ext_modules.append(darwin_ext)

    # sometimes there's no need to cythonize
    # this breaks chained commands like 'clean sdist'
    cythonizing = (
        len(sys.argv) > 1
        and sys.argv[1] not in (("clean", "egg_info", "--help-commands", "--version"))
        and "--help" not in sys.argv[1:]
    )

    if cythonize and cythonizing:
        # 3str is the default in Cython3 and we do not support older Cython releases.
        # we only set this to avoid the related FutureWarning from Cython3.
        cython_opts = dict(compiler_directives={"language_level": "3str", "warn.unreachable": True})

        if not is_win32:
            # Compile .pyx extensions to .c in parallel; does not work on Windows
            cython_opts["nthreads"] = cpu_threads

        # generate C code from Cython for ALL supported platforms, so we have them in the sdist.
        # the sdist does not require Cython at install time, so we need all as C.
        cythonize(
            [posix_ext, linux_ext, syncfilerange_ext, freebsd_ext, netbsd_ext, darwin_ext, windows_ext], **cython_opts
        )
        # generate C code from Cython for THIS platform (and for all platform-independent Cython parts).
        ext_modules = cythonize(ext_modules, **cython_opts)


def long_desc_from_readme():
    with open("README.rst") as fd:
        long_description = fd.read()
        # remove header, but have one \n before first headline
        start = long_description.find("What is BorgBackup?")
        assert start >= 0
        long_description = "\n" + long_description[start:]
        # remove badges
        long_description = re.compile(r"^\.\. start-badges.*^\.\. end-badges", re.M | re.S).sub("", long_description)
        # remove unknown directives
        long_description = re.compile(r"^\.\. highlight:: \w+$", re.M).sub("", long_description)
        return long_description


setup(cmdclass=cmdclass, ext_modules=ext_modules, long_description=long_desc_from_readme())
