# -*- encoding: utf-8 *-*
#!/usr/bin/env python
import os
import sys
from glob import glob
import darc

min_python = (3, 2)
if sys.version_info < min_python:
    print("Darc requires Python %d.%d or later" % min_python)
    sys.exit(1)

try:
    import Cython
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fake_pyrex"))
except ImportError:
    pass

from distutils.core import setup
from distutils.extension import Extension
from distutils.command.sdist import sdist

chunker_source = 'darc/chunker.pyx'
hashindex_source = 'darc/hashindex.pyx'

try:
    from Cython.Distutils import build_ext
    import Cython.Compiler.Main as cython_compiler

    class Sdist(sdist):
        def __init__(self, *args, **kwargs):
            for src in glob('darc/*.pyx'):
                cython_compiler.compile(glob('darc/*.pyx'),
                                        cython_compiler.default_options)
            sdist.__init__(self, *args, **kwargs)

        def make_distribution(self):
            self.filelist += ['darc/chunker.c', 'darc/chunker.h', 'darc/hashindex.c', 'darc/hashindex.h']
            sdist.make_distribution(self)

except ImportError:
    chunker_source = chunker_source.replace('.pyx', '.c')
    hashindex_source = hashindex_source.replace('.pyx', '.c')
    from distutils.command.build_ext import build_ext
    Sdist = sdist
    if not os.path.exists(chunker_source) or not os.path.exists(hashindex_source):
        raise ImportError('The GIT version of darc needs Cython. Install Cython or use a released version')

setup(name='darc',
      version=darc.__version__,
      author='Jonas Borgström',
      author_email='jonas@borgstrom.se',
      url='http://github.com/jborg/darc/',
      packages=['darc'],
      cmdclass={'build_ext': build_ext, 'sdist': Sdist},
      ext_modules=[
      Extension('darc.chunker', [chunker_source]),
      Extension('darc.hashindex', [hashindex_source])],
      scripts=['scripts/darc'],
    )

