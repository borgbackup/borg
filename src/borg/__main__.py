import sys
import os

# On Windows, loading the bundled libcrypto DLL fails if the folder
# containing the DLL is not in the search path. The DLL is shipped
# with Python in the "DLLs" folder, so let's add this folder
# to the PATH. The folder is always in sys.path; get it from there.
if sys.platform.startswith('win32'):
    # Keep it as an iterable to support multiple folders that contain "DLLs".
    dll_path = (p for p in sys.path if 'DLLs' in os.path.normpath(p).split(os.path.sep))
    os.environ['PATH'] = os.pathsep.join(dll_path) + os.pathsep + os.environ['PATH']


from borg.archiver import main
main()
