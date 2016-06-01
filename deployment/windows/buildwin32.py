import shutil
import os
import subprocess
import sys
from modulefinder import ModuleFinder

import borg

# Creates standalone Windows executable
# First build by following instructions from installation.rst

builddir = 'win32exe'

if os.path.exists(builddir):
    shutil.rmtree(builddir)
os.mkdir(builddir)
os.mkdir(builddir + '/bin')
os.mkdir(builddir + '/lib')

print('Compiling wrapper')

gccpath = ''  # check for compiler, path needed later
for p in os.environ['PATH'].split(';'):
    if os.path.exists(os.path.join(p, 'gcc.exe')):
        gccpath = p
        break
if gccpath == '':
    print('gcc not found.')
    exit(1)

source = open('wrapper.c', 'w')
source.write(
"""
#include <python3.5m/python.h>
#include <windows.h>
#include <wchar.h>
#include "Shlwapi.h"

int wmain(int argc , wchar_t *argv[] )
{

    wchar_t *program = argv[0];
    Py_SetProgramName(program);
    Py_Initialize();

    PySys_SetArgv(argc, argv);

    PyRun_SimpleString("from runpy import run_module\\n"
                       "run_module('borg')");

    Py_Finalize();
    return 0;
}
""")
source.close()
subprocess.check_call('gcc wrapper.c -lpython3.5m -lshlwapi -municode -o ' + builddir + '/bin/borg.exe')
os.remove('wrapper.c')

print('Searching modules')

modulepath = os.path.abspath(os.path.join(gccpath, '../lib/python3.5/'))

shutil.copytree(os.path.join(modulepath, 'encodings'), os.path.join(builddir, 'lib/python3.5/encodings'))

finder = ModuleFinder()
finder.run_script(os.path.join(borg.__path__[0], '__main__.py'))
extramodules = [os.path.join(modulepath, 'site.py')]

for module in extramodules:
    finder.run_script(module)

print('Copying files')


def finddlls(exe):
    re = []
    output = subprocess.check_output(['ntldd', '-R', exe])
    for line in output.decode('utf-8').split('\n'):
        if 'not found' in line:
            continue
        if 'windows' in line.lower():
            continue
        words = line.split()
        if len(words) < 3:
            if len(words) == 2:
                re.append(words[0])
            continue
        dll = words[2]
        re.append(dll)
    return re

items = finder.modules.items()
for name, mod in items:
    file = mod.__file__
    if file is None:
        continue
    lib = file.find('lib')
    if lib == -1:
        # Part of the borg package
        relpath = os.path.relpath(file)[4:]
        os.makedirs(os.path.join(builddir, 'lib', 'python3.5', os.path.split(relpath)[0]), exist_ok=True)
        shutil.copyfile(file, os.path.join(builddir, 'lib', 'python3.5', relpath))
        continue
    relativepath = file[file.find('lib')+4:]
    os.makedirs(os.path.join(builddir, 'lib', os.path.split(relativepath)[0]), exist_ok=True)
    shutil.copyfile(file, os.path.join(builddir, 'lib', relativepath))
    if file[-4:] == '.dll' or file[-4:] == '.DLL':
        for dll in finddlls(file):
            if builddir not in dll:
                shutil.copyfile(dll, os.path.join(builddir, 'bin', os.path.split(dll)[1]))
for dll in finddlls(os.path.join(builddir, "bin/borg.exe")):
    if builddir not in dll:
        shutil.copyfile(dll, os.path.join(builddir, 'bin', os.path.split(dll)[1]))

shutil.copyfile('src/borg/__main__.py', os.path.join(builddir, 'lib/python3.5/borg/__main__.py'))

for extmodule in ['src/borg/chunker-cpython-35m.dll', 'src/borg/compress-cpython-35m.dll', 'src/borg/crypto-cpython-35m.dll', 'src/borg/hashindex-cpython-35m.dll']:
    for dll in finddlls(extmodule):
        if builddir not in dll:
            shutil.copyfile(dll, os.path.join(builddir, 'bin', os.path.split(dll)[1]))
