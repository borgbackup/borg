# -*- coding: utf-8 -*-

from distutils.core import Command
import gettext
import locale
import pkg_resources
import os
import sys

from borg.support import msgfmt

prog = 'borg'

# Initialize gettext, taken from deluge 1.3.3 (GPL3)
try:
    locale.setlocale(locale.LC_ALL, '')
    if hasattr(locale, "bindtextdomain"):
        locale.bindtextdomain(prog, pkg_resources.resource_filename(prog, "po"))
    if hasattr(locale, "textdomain"):
        locale.textdomain(prog)
    gettext.install(prog, pkg_resources.resource_filename(prog, "po"), names='ngettext')
except Exception as e:
    print("Unable to initialize translations: %s" % e, file=sys.stderr)
    import builtins
    builtins.__dict__['_'] = lambda x: x

# stolen from deluge-1.3.3 (GPL3)
class build_trans(Command):
    description = 'Compile .po files into .mo files'

    user_options = [
            ('build-lib=', None, "lib build folder"),
            ('po-dir=', 'p', 'directory where .po files are stored, relative to the current directory'),
    ]

    def initialize_options(self):
        self.build_lib = None
        self.po_dir = 'po/'

    def finalize_options(self):
        self.set_undefined_options('build', ('build_lib', 'build_lib'))

    def run(self):
        po_dir = self.po_dir

        appname = self.distribution.get_name()
        self.announce('compiling po files from %s' % po_dir, 2)
        uptoDate = False
        for path, names, filenames in os.walk(po_dir):
            for f in filenames:
                uptoDate = False
                if f.endswith('.po'):
                    lang = f[:len(f) - 3]
                    src = os.path.join(path, f)
                    dest_path = os.path.join(self.build_lib, appname, 'po', lang, \
                        'LC_MESSAGES')
                    dest = os.path.join(dest_path, appname + '.mo')
                    if not os.path.exists(dest_path):
                        os.makedirs(dest_path)
                    if not os.path.exists(dest):
                        sys.stdout.write('%s, ' % lang)
                        sys.stdout.flush()
                        msgfmt.make(src, dest)
                    else:
                        src_mtime = os.stat(src)[8]
                        dest_mtime = os.stat(dest)[8]
                        if src_mtime > dest_mtime:
                            sys.stdout.write('%s, ' % lang)
                            sys.stdout.flush()
                            msgfmt.make(src, dest)
                        else:
                            uptoDate = True
                            
        if uptoDate:
            self.announce('po files already upto date.', 2)
        else:
            self.announce('done', 2)
