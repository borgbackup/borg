# Build a wheel and single file executable

# Configure the build environment
& $PSScriptRoot\win-setup-build-env.ps1

# Clean the old build
python setup.py clean

# Build the extension inplace
python setup.py build_ext --inplace

# Run pip install to install install_requires of borg.
pip install -v -e .

# Build the wheel
python setup.py bdist_wheel

pyinstaller -y scripts/borg.exe.spec
