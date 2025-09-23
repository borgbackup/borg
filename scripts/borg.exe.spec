# -*- mode: python -*-
# This PyInstaller spec file is used to build Borg binaries on POSIX platforms and Windows.

import os, sys

is_win32 = sys.platform.startswith('win32')

# Note: SPEC contains the spec file argument given to pyinstaller
here = os.path.dirname(os.path.abspath(SPEC))
basepath = os.path.abspath(os.path.join(here, '..'))

if is_win32:
    hiddenimports = ['borghash']
else:
    hiddenimports = ['borg.platform.posix', 'borghash']

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
                '_ssl', 'ssl',
                'pkg_resources',  # avoid pkg_resources related warnings
             ],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

if sys.platform == 'darwin':
    # do not bundle the osxfuse libraries, so we do not get a version
    # mismatch to the installed kernel driver of osxfuse.
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
          console=True,
          icon='NONE')

# Build a directory-based binary in addition to a packed
# single-file binary. This allows you to look at all included
# files easily (e.g., without having to strace or halt the built binary
# and introspect /tmp). It also avoids unpacking all libraries when
# running the app, which is better for application signing on various OSes.
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
