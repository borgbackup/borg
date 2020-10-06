# -*- mode: python -*-
# this pyinstaller spec file is used to build borg binaries on posix platforms

import os, sys

# Note: SPEC contains the spec file argument given to pyinstaller
here = os.path.dirname(os.path.abspath(SPEC))
basepath = os.path.abspath(os.path.join(here, '..'))

block_cipher = None

a = Analysis([os.path.join(basepath, 'src/borg/__main__.py'), ],
             pathex=[basepath, ],
             binaries=[],
             datas=[
                 ('../src/borg/paperkey.html', 'borg'),
             ],
             hiddenimports=['borg.platform.posix'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[
                '_ssl', 'ssl',
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
          console=True )

# Build a directory-based binary in addition to a packed
# single file. This allows one to easily look at all included
# files (e.g. without having to strace or halt the built binary
# and introspect /tmp). Also avoids unpacking all libs when
# running the app, which is better for app signing on various OS.
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
