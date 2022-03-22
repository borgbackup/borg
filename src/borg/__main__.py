import sys
import os

# On windows loading the bundled libcrypto dll fails if the folder
# containing the dll is not in the search path. The dll is shipped
# with python in the "DLLs" folder, so let's add this folder
# to the path. The folder is always in sys.path, get it from there.
if sys.platform.startswith("win32"):
    # Keep it an iterable to support multiple folder which contain "DLLs".
    dll_path = (p for p in sys.path if "DLLs" in os.path.normpath(p).split(os.path.sep))
    os.environ["PATH"] = os.pathsep.join(dll_path) + os.pathsep + os.environ["PATH"]


from borg.archiver import main

main()
