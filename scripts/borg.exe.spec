# -*- mode: python -*-
# this pyinstaller spec file is used to build borg binaries on posix platforms

import os, sys

basepath = '/vagrant/borg/borg'

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

if False:
    # Enable this block to build a directory-based binary instead of
    # a packed single file. This allows to easily look at all included
    # files (e.g. without having to strace or halt the built binary
    # and introspect /tmp).
    coll = COLLECT(exe,
                   a.binaries,
                   a.zipfiles,
                   a.datas,
                   strip=False,
                   upx=True,
                   name='borg-dir')
