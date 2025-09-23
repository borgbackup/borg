import sys
import os

# On Windows, loading the bundled libcrypto DLL fails if the folder
# containing the DLL is not in the search path. The DLL is shipped
# with Python in the "DLLs" folder, so we add this folder
# to the PATH. The folder is always present in sys.path; get it from there.
if sys.platform.startswith("win32"):
    # Keep it an iterable to support multiple folders that contain "DLLs".
    dll_path = (p for p in sys.path if "DLLs" in os.path.normpath(p).split(os.path.sep))
    os.environ["PATH"] = os.pathsep.join(dll_path) + os.pathsep + os.environ["PATH"]


# Note: absolute import from "borg"; PyInstaller binaries do not work without this.
from borg.archiver import main

main()
