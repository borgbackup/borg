# -*- mode: python -*-
# this pyinstaller spec file is used to build borg binaries on posix platforms

import os, sys

#basepath = '/vagrant/borg/borg'
basepath = '/home/borg/borg/borg'

block_cipher = None

a = Analysis([os.path.join(basepath, 'src/borg/__main__.py'), ],
             pathex=[basepath, ],
             binaries=[],
             datas=[],
             hiddenimports=['borg.platform.posix'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
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
          exclude_binaries=True,
          name='borg.real',
          debug=False,
          strip=False,
          upx=False,
          console=True )

coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=False,
               name='borg.android')

