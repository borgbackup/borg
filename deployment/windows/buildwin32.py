import shutil
import os
import subprocess
import sys
from modulefinder import ModuleFinder
import zipfile

# Creates standalone Windows executable
# First build by following instructions from installation.rst

builddir = 'win32exe'

if os.path.exists(builddir):
    shutil.rmtree(builddir)
os.mkdir(builddir)
os.mkdir(builddir + '/bin')
library = zipfile.PyZipFile(os.path.join(builddir, 'library.zip'), mode='w')

print('Compiling wrapper')

gccpath = ''  # check for compiler, path needed later
for p in os.environ['PATH'].split(';'):
    if os.path.exists(os.path.join(p, 'g++.exe')):
        gccpath = p
        break
if gccpath == '':
    print('g++ not found.')
    exit(1)

source = open('wrapper.c', 'w')
source.write(
"""
#include <python3.5m/python.h>
#include <windows.h>
#include <wchar.h>
#include <string>
#include "Shlwapi.h"

int wmain(int argc , wchar_t *argv[] )
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    PathRemoveFileSpecW(path);
    std::wstring selfpath(path);
    std::wstring libpath = selfpath + L"/library.zip;" + selfpath + L"/bin";
    SetDllDirectoryW(path);

    Py_SetPath(libpath.c_str());
    Py_SetProgramName(argv[0]);
    Py_Initialize();
    PySys_SetArgv(argc, argv);

    PyImport_ImportModule("encodings.idna");
    PyRun_SimpleString("from runpy import run_module\\n"
                       "run_module('borg')");

    Py_Finalize();
    return 0;
}
""")
source.close()
subprocess.check_call('g++ wrapper.c -lpython3.5m -lshlwapi -municode -o ' + builddir + '/borg.exe')
os.remove('wrapper.c')

print('Searching modules')

modulepath = os.path.abspath(os.path.join(gccpath, '../lib/python3.5/'))

# Bundle all encodings - In theory user may use any encoding in command prompt
for file in os.listdir(os.path.join(modulepath, 'encodings')):
    if os.path.isfile(os.path.join(modulepath, 'encodings', file)):
        library.write(os.path.join(modulepath, 'encodings', file), os.path.join('encodings', file))

finder = ModuleFinder()
finder.run_script('src/borg/__main__.py')

# For some reason modulefinder does not find these, add them manually
extramodules = [os.path.join(modulepath, 'site.py'), os.path.join(modulepath, 'encodings/idna.py'),
    os.path.join(modulepath, 'stringprep.py')]

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
        os.makedirs(os.path.join(builddir, 'bin', os.path.split(relpath)[0]), exist_ok=True)
        shutil.copyfile(file, os.path.join(builddir, 'bin', relpath))
    else:
        relativepath = file[file.find('lib')+len('lib/python3.5/'):]
        if 'encodings' in file:
            continue
        if relativepath not in library.namelist():
            if relativepath.startswith('site-packages'):
                relativepath = relativepath[len('site-packages/'):]
            library.write(file, relativepath)
    if file.endswith(('dll', 'DLL')):
        shutil.copyfile(file, os.path.join(builddir, 'bin', os.path.split(file)[1]))
        for dll in finddlls(file):
            if builddir not in dll:
                shutil.copyfile(dll, os.path.join(builddir, os.path.split(dll)[1]))
for dll in finddlls(os.path.join(builddir, "borg.exe")):
    if builddir not in dll:
        shutil.copyfile(dll, os.path.join(builddir, os.path.split(dll)[1]))

shutil.copyfile(os.path.join('src', 'borg', '__main__.py'), os.path.join(builddir, 'bin', 'borg', '__main__.py'))
library.write(os.path.join(modulepath, 'site.py'), 'site.py')

for extmodule in ['src/borg/chunker-cpython-35m.dll', 'src/borg/compress-cpython-35m.dll',
    'src/borg/crypto-cpython-35m.dll', 'src/borg/hashindex-cpython-35m.dll']:
    for dll in finddlls(extmodule):
        if builddir not in dll:
            shutil.copyfile(dll, os.path.join(builddir, os.path.split(dll)[1]))
