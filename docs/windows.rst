.. include:: global.rst.inc
.. _windows:

Building on windows (MSYS2)
===========================

This is step by step guide to build |project_name| on windows using MSYS2

1. Download MSYS from https://msys2.github.io/ and follow install instructions. This guide assumes 64bit version.
2. In msys commandline run `pacman -S mingw-w64-x86_64-python3 git mingw-w64-x86_64-lz4 mingw-w64-x86_64-python3-pip mingw-w64-x86_64-cython mingw-w64-x86_64-gcc` to install necessary packages.
3. Close msys. Navigate msys install directory and open `mingw64_shell.bat`
4. Clone borg from github
5. Run these commands in the borg source directory
```
pip3 install -e .fake
echo "version = '$(git describe --tags)'" > borg/_version.py
```
6. To run from windows commandline add msysdir\\mingw64\\bin to windows path enviroment variable and use python3 as python command