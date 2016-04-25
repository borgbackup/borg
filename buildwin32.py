import shutil
import os
import subprocess
from modulefinder import ModuleFinder

#Creates standalone Windows executable
#First build by following instructions from installation.rst

builddir = 'win32exe'

if os.path.exists(builddir):
    shutil.rmtree(builddir)
os.mkdir(builddir)
os.mkdir(builddir + '/bin')
os.mkdir(builddir + '/lib')

print('Compiling wrapper')

gccpath = '' # check for compiler, path needed later
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

    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    PathRemoveFileSpecW(path);

    FILE* file_1 = _wfopen(wcsncat(path, L"/borg/__main__.py", 17), L"r");
    PyRun_AnyFile(file_1, "borg/__main__.py");

    Py_Finalize();
    PyMem_RawFree(program);
    return 0;
}
""")
source.close()
subprocess.run('gcc wrapper.c -lpython3.5m -lshlwapi -municode -o ' + builddir + '/bin/borg.exe')
os.remove('wrapper.c')

print('Searching modules')

modulepath = os.path.abspath(os.path.join(gccpath, '../lib/python3.5/'))

shutil.copytree(os.path.join(modulepath, 'encodings'), os.path.join(builddir, 'lib/python3.5/encodings'))

finder = ModuleFinder()
finder.run_script('borg/__main__.py')
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
        relpath = os.path.relpath(file)
        os.makedirs(os.path.join(builddir, 'bin', os.path.split(relpath)[0]), exist_ok=True)
        shutil.copyfile(file, os.path.join(builddir, 'bin', relpath))
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
shutil.copyfile('borg/__main__.py', os.path.join(builddir, 'bin/borg/__main__.py'))

for extmodule in ['borg/chunker-cpython-35m.dll', 'borg/compress-cpython-35m.dll', 'borg/crypto-cpython-35m.dll', 'borg/hashindex-cpython-35m.dll']:
    for dll in finddlls(extmodule):
        if builddir not in dll:
            shutil.copyfile(dll, os.path.join(builddir, 'bin', os.path.split(dll)[1]))
