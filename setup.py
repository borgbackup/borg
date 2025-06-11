# borgbackup - main setup code (extension building here, rest see pyproject.toml)

import os
import re
import sys
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

# Number of threads to use for cythonize, not used on windows
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

# Extra cflags for all extensions, usually just warnings we want to enable explicitly
cflags = ["-Wall", "-Wextra", "-Wpointer-arith", "-Wno-unreachable-code-fallthrough"]

compress_source = "src/borg/compress.pyx"
crypto_ll_source = "src/borg/crypto/low_level.pyx"
buzhash_source = "src/borg/chunkers/buzhash.pyx"
buzhash64_source = "src/borg/chunkers/buzhash64.pyx"
reader_source = "src/borg/chunkers/reader.pyx"
hashindex_source = "src/borg/hashindex.pyx"
item_source = "src/borg/item.pyx"
checksums_source = "src/borg/checksums.pyx"
platform_posix_source = "src/borg/platform/posix.pyx"
platform_linux_source = "src/borg/platform/linux.pyx"
platform_syncfilerange_source = "src/borg/platform/syncfilerange.pyx"
platform_darwin_source = "src/borg/platform/darwin.pyx"
platform_freebsd_source = "src/borg/platform/freebsd.pyx"
platform_windows_source = "src/borg/platform/windows.pyx"

cython_sources = [
    compress_source,
    crypto_ll_source,
    buzhash_source,
    buzhash64_source,
    reader_source,
    hashindex_source,
    item_source,
    checksums_source,
    platform_posix_source,
    platform_linux_source,
    platform_syncfilerange_source,
    platform_freebsd_source,
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
            "The GIT version of Borg needs a working Cython. "
            + "Install or fix Cython or use a released borg version. "
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
        print("Warning: can not import pkgconfig python package.")
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
        crypto_ext_lib = lib_ext_kwargs(pc, "BORG_OPENSSL_PREFIX", "libcrypto", "libcrypto", ">=1.1.1", lib_subdir="")
    elif is_openbsd:
        # Use openssl (not libressl) because we need AES-OCB via EVP api. Link
        # it statically to avoid conflicting with shared libcrypto from the base
        # OS pulled in via dependencies.
        openssl_prefix = os.environ.get("BORG_OPENSSL_PREFIX", "/usr/local")
        openssl_name = os.environ.get("BORG_OPENSSL_NAME", "eopenssl33")
        crypto_ext_lib = dict(
            include_dirs=[os.path.join(openssl_prefix, "include", openssl_name)],
            extra_objects=[os.path.join(openssl_prefix, "lib", openssl_name, "libcrypto.a")],
        )
    else:
        crypto_ext_lib = lib_ext_kwargs(pc, "BORG_OPENSSL_PREFIX", "crypto", "libcrypto", ">=1.1.1")

    crypto_ext_kwargs = members_appended(
        dict(sources=[crypto_ll_source]), crypto_ext_lib, dict(extra_compile_args=cflags)
    )

    compress_ext_kwargs = members_appended(
        dict(sources=[compress_source]),
        lib_ext_kwargs(pc, "BORG_LIBLZ4_PREFIX", "lz4", "liblz4", ">= 1.7.0"),
        lib_ext_kwargs(pc, "BORG_LIBZSTD_PREFIX", "zstd", "libzstd", ">= 1.3.0"),
        dict(extra_compile_args=cflags),
    )

    checksums_ext_kwargs = members_appended(
        dict(sources=[checksums_source]),
        lib_ext_kwargs(pc, "BORG_LIBXXHASH_PREFIX", "xxhash", "libxxhash", ">= 0.7.3"),
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

    # note: _chunker.c is a relatively complex/large piece of handwritten C code,
    # thus we undef NDEBUG for it, so the compiled code will contain and execute assert().
    ext_modules += [
        Extension("borg.crypto.low_level", **crypto_ext_kwargs),
        Extension("borg.compress", **compress_ext_kwargs),
        Extension("borg.hashindex", [hashindex_source], extra_compile_args=cflags),
        Extension("borg.item", [item_source], extra_compile_args=cflags),
        Extension("borg.chunkers.buzhash", [buzhash_source], extra_compile_args=cflags, undef_macros=["NDEBUG"]),
        Extension("borg.chunkers.buzhash64", [buzhash64_source], extra_compile_args=cflags, undef_macros=["NDEBUG"]),
        Extension("borg.chunkers.reader", [reader_source], extra_compile_args=cflags, undef_macros=["NDEBUG"]),
        Extension("borg.checksums", **checksums_ext_kwargs),
    ]

    posix_ext = Extension("borg.platform.posix", [platform_posix_source], extra_compile_args=cflags)
    linux_ext = Extension("borg.platform.linux", **linux_ext_kwargs)

    syncfilerange_ext = Extension(
        "borg.platform.syncfilerange", [platform_syncfilerange_source], extra_compile_args=cflags
    )
    freebsd_ext = Extension("borg.platform.freebsd", [platform_freebsd_source], extra_compile_args=cflags)
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
        cython_opts = dict(compiler_directives={"language_level": "3str"})
        if not is_win32:
            # compile .pyx extensions to .c in parallel, does not work on windows
            cython_opts["nthreads"] = cpu_threads

        # generate C code from Cython for ALL supported platforms, so we have them in the sdist.
        # the sdist does not require Cython at install time, so we need all as C.
        cythonize([posix_ext, linux_ext, syncfilerange_ext, freebsd_ext, darwin_ext, windows_ext], **cython_opts)
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
