# -*- mode: python -*-
# This PyInstaller spec file is used to build Borg binaries on POSIX platforms.

import os, sys

is_win32 = sys.platform.startswith('win32')

# Note: SPEC contains the spec file argument given to pyinstaller
here = os.path.dirname(os.path.abspath(SPEC))
basepath = os.path.abspath(os.path.join(here, '..'))

if is_win32:
    hiddenimports = []
else:
    hiddenimports = ['borg.platform.posix', ]

block_cipher = None

a = Analysis([os.path.join(basepath, 'src', 'borg', '__main__.py'), ],
             pathex=[basepath, ],
             binaries=[],
             datas=[
                (os.path.join(basepath, 'src', 'borg', 'paperkey.html'), 'borg'),
             ],
             hiddenimports=hiddenimports,
             hookspath=[],
             runtime_hooks=[],
             excludes=[
                # '_ssl', 'ssl',  # do not exclude these, needed for pyfuse3/trio
                'pkg_resources',  # avoid pkg_resources related warnings
             ],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

if sys.platform == 'darwin':
    # Do not bundle the macFUSE libraries to avoid a version
    # mismatch with the installed macFUSE kernel driver.
    a.binaries = [b for b in a.binaries if 'libosxfuse' not in b[0]]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='borg.exe',
          debug=False,
          strip=False,
          upx=True,
          console=True)

# Build a directory-based binary in addition to a packed
# single file. This allows one to easily look at all included
# files (e.g., without having to strace or halt the built binary
# and introspect /tmp). Also avoids unpacking all libraries when
# running the app, which is better for app signing on various operating systems.
slim_exe = EXE(pyz,
            a.scripts,
            exclude_binaries=True,
            name='borg.exe',
            debug=False,
            strip=False,
            upx=False,
            console=True)

coll = COLLECT(slim_exe,
                a.binaries,
                a.zipfiles,
                a.datas,
                strip=False,
                upx=False,
                name='borg-dir')
