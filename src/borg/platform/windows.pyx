#cython: language_level=3

import json
import os.path
from libc.stddef cimport wchar_t
from libc.stdint cimport uint16_t, uint32_t, uint64_t, int64_t
cimport cpython.array
import array

import platform

import ctypes
import ctypes.wintypes
import msvcrt

PeekNamedPipe = ctypes.windll.kernel32.PeekNamedPipe
PeekNamedPipe.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD,
    ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.POINTER(ctypes.wintypes.DWORD),
    ctypes.POINTER(ctypes.wintypes.DWORD)]
PeekNamedPipe.restype = ctypes.c_bool

API_VERSION = 3


cdef extern from 'stdlib.h':
    void free(void* ptr)
    void* malloc(size_t)
    void* calloc(size_t, size_t)


cdef extern from 'Python.h':
    wchar_t* PyUnicode_AsWideCharString(object, Py_ssize_t *)
    object PyUnicode_FromWideChar(const wchar_t*, Py_ssize_t)
    void* PyMem_Malloc(int)
    void PyMem_Free(void*)


cdef extern from 'windows.h':
    ctypedef int HLOCAL
    ctypedef wchar_t* LPCTSTR
    ctypedef char BYTE
    ctypedef int HLOCAL
    ctypedef uint32_t DWORD
    ctypedef DWORD* LPDWORD
    ctypedef int BOOL
    ctypedef BYTE* PSID
    ctypedef void* HANDLE
    struct _ACL:
        uint16_t AceCount

    cdef enum _SID_NAME_USE:
        SidTypeUser,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer,
        SidTypeLabel

    cdef enum _STREAM_INFO_LEVELS:
        FindStreamInfoStandard

    struct _LARGE_INTEGER:
        int64_t QuadPart
    struct _WIN32_FIND_STREAM_DATA:
        _LARGE_INTEGER StreamSize
        wchar_t[296] cStreamName # MAX_PATH + 36

    struct _LUID:
        pass

    struct _LUID_AND_ATTRIBUTES:
        _LUID Luid
        DWORD Attributes

    struct _TOKEN_PRIVILEGES:
        DWORD PrivilegeCount
        _LUID_AND_ATTRIBUTES Privileges[1]

    HLOCAL LocalFree(HLOCAL)
    DWORD GetLastError()
    void SetLastError(DWORD)

    DWORD FormatMessageW(DWORD, void*, DWORD, DWORD, wchar_t*, DWORD, void*)

    HANDLE FindFirstStreamW(wchar_t*, _STREAM_INFO_LEVELS, void*, DWORD)
    BOOL FindNextStreamW(HANDLE, void*)
    BOOL FindClose(HANDLE)

    BOOL InitializeSecurityDescriptor(BYTE*, DWORD)

    BOOL LookupAccountNameW(LPCTSTR, LPCTSTR, PSID, LPDWORD, LPCTSTR, LPDWORD, _SID_NAME_USE*)
    BOOL GetSecurityDescriptorDacl(PSID, BOOL*, _ACL**, BOOL*)

    BOOL OpenProcessToken(HANDLE, DWORD, HANDLE*)
    BOOL OpenThreadToken(HANDLE, DWORD, BOOL, HANDLE*)
    BOOL LookupPrivilegeValueW(wchar_t*, wchar_t*, _LUID*)
    BOOL AdjustTokenPrivileges(HANDLE, BOOL, _TOKEN_PRIVILEGES*, DWORD, _TOKEN_PRIVILEGES*, DWORD*)

    HANDLE GetCurrentThread()
    HANDLE GetCurrentProcess()

    cdef extern int ERROR_SUCCESS
    cdef extern int ERROR_INSUFFICIENT_BUFFER
    cdef extern int ERROR_INVALID_SID
    cdef extern int ERROR_NONE_MAPPED
    cdef extern int ERROR_HANDLE_EOF

    cdef extern int OWNER_SECURITY_INFORMATION
    cdef extern int GROUP_SECURITY_INFORMATION
    cdef extern int DACL_SECURITY_INFORMATION
    cdef extern int SACL_SECURITY_INFORMATION
    cdef extern int LABEL_SECURITY_INFORMATION
    cdef extern int ATTRIBUTE_SECURITY_INFORMATION
    cdef extern int SCOPE_SECURITY_INFORMATION
    cdef extern int BACKUP_SECURITY_INFORMATION
    cdef extern int UNPROTECTED_SACL_SECURITY_INFORMATION
    cdef extern int UNPROTECTED_DACL_SECURITY_INFORMATION
    cdef extern int PROTECTED_SACL_SECURITY_INFORMATION
    cdef extern int PROTECTED_DACL_SECURITY_INFORMATION

    cdef extern int SECURITY_DESCRIPTOR_MIN_LENGTH

    cdef extern int FORMAT_MESSAGE_ALLOCATE_BUFFER
    cdef extern int FORMAT_MESSAGE_FROM_SYSTEM
    cdef extern int FORMAT_MESSAGE_IGNORE_INSERTS

    cdef extern int INVALID_HANDLE_VALUE

    cdef extern DWORD SE_PRIVILEGE_ENABLED

    cdef extern int TOKEN_ADJUST_PRIVILEGES
    cdef extern int TOKEN_QUERY

cdef extern from 'accctrl.h':
    ctypedef enum _SE_OBJECT_TYPE:
        SE_FILE_OBJECT
    ctypedef _SE_OBJECT_TYPE SE_OBJECT_TYPE
    struct _TRUSTEE_W:
        uint16_t TrusteeForm
        uint16_t TrusteeType
        LPCTSTR ptstrName

    struct _EXPLICIT_ACCESS_W:
        DWORD grfAccessPermissions
        uint16_t grfAccessMode
        DWORD grfInheritance
        _TRUSTEE_W Trustee

    cdef extern uint16_t TRUSTEE_IS_SID
    cdef extern uint16_t TRUSTEE_IS_NAME
    cdef extern uint16_t TRUSTEE_BAD_FORM

    cdef extern int NO_INHERITANCE
    cdef extern int INHERIT_NO_PROPAGATE
    cdef extern int INHERIT_ONLY
    cdef extern int INHERITED_ACCESS_ENTRY

    DWORD GetExplicitEntriesFromAclW(_ACL*, uint32_t*, _EXPLICIT_ACCESS_W**)


cdef extern from 'Sddl.h':
    ctypedef int* LPBOOL

    BOOL GetFileSecurityW(LPCTSTR, int, PSID, DWORD, LPDWORD)
    BOOL GetSecurityDescriptorOwner(PSID, PSID*, LPBOOL)
    BOOL LookupAccountSidW(LPCTSTR, PSID, LPCTSTR, LPDWORD, LPCTSTR, LPDWORD, _SID_NAME_USE*)
    BOOL ConvertSidToStringSidW(PSID, LPCTSTR*)
    BOOL ConvertStringSidToSidW(LPCTSTR, PSID*)
    BOOL ConvertSecurityDescriptorToStringSecurityDescriptorW(BYTE*, DWORD, int, LPCTSTR*, int*)

    cdef extern int SDDL_REVISION_1


cdef extern from 'Aclapi.h':
    ctypedef void* PACL
    DWORD GetNamedSecurityInfoW(LPCTSTR, SE_OBJECT_TYPE, DWORD, PSID*, PSID*, PACL*, PACL*, _ACL**)
    DWORD SetNamedSecurityInfoW(LPCTSTR, int, int, PSID, PSID, PACL, PACL)
    DWORD SetEntriesInAclW(unsigned int, _EXPLICIT_ACCESS_W*, PACL, _ACL**)
    DWORD LookupSecurityDescriptorPartsW(_TRUSTEE_W**, _TRUSTEE_W**, uint32_t*, _EXPLICIT_ACCESS_W**, uint32_t*, _EXPLICIT_ACCESS_W**, PSID)


def raise_error(api, path=''):
    cdef wchar_t *error_message
    error = GetLastError()
    if not error:
        return
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, error, 0, <wchar_t*>&error_message, 0, NULL)
    error_string = PyUnicode_FromWideChar(error_message, -1)
    LocalFree(<HLOCAL>error_message)
    error_string = api + ': ' + error_string
    if path:
        raise OSError(error, error_string, path)
    else:
        raise OSError(error, error_string)


permissions_enabled = False # Have we tried to acquire permissions for SACL
permissions_granted = False # Did we get them


cdef enable_permissions():
    global permissions_enabled
    global permissions_granted
    if permissions_enabled:
        return
    permissions_enabled = True
    cdef HANDLE hToken
    OpenProcessToken(GetCurrentProcess() , TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)

    cdef _TOKEN_PRIVILEGES tp
    cdef _LUID luid
    cdef _TOKEN_PRIVILEGES tpPrevious
    cdef DWORD cbPrevious=sizeof(_TOKEN_PRIVILEGES)

    cdef wchar_t* privilege = PyUnicode_AsWideCharString("SeSecurityPrivilege", NULL)
    if not LookupPrivilegeValueW( NULL, privilege, &luid ):
        permissions_granted = False
        print("Warning: permissions to read auditing settings (SACL) denied. Try running as admin.")
        return

    tp.PrivilegeCount           = 1
    tp.Privileges[0].Luid       = luid
    tp.Privileges[0].Attributes = 0

    AdjustTokenPrivileges(hToken, 0, &tp, sizeof(_TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious)
    if GetLastError() != ERROR_SUCCESS:
        permissions_granted = False
        print("Warning: permissions to read auditing settings (SACL) denied. Try running as admin.")
        return

    tpPrevious.PrivilegeCount           = 1
    tpPrevious.Privileges[0].Luid       = luid
    tpPrevious.Privileges[0].Attributes = tpPrevious.Privileges[0].Attributes | SE_PRIVILEGE_ENABLED

    AdjustTokenPrivileges(hToken, 0, &tpPrevious, cbPrevious, NULL, NULL)

    if GetLastError() != ERROR_SUCCESS:
        permissions_granted = False
        print("Warning: permissions to read auditing settings (SACL) denied. Try running as admin.")
        return


cdef PSID _get_file_security(filename, int request):
    cdef DWORD length = 0
    # N.B. This query may fail with ERROR_INVALID_FUNCTION
    # for some filesystems.
    cdef wchar_t* wcharfilename = PyUnicode_AsWideCharString(filename, NULL)
    GetFileSecurityW(wcharfilename, request, NULL, 0, &length)
    if GetLastError() == ERROR_INSUFFICIENT_BUFFER:
        SetLastError(0)
    else:
        raise_error('GetFileSecurityW', filename)
        return NULL
    cdef BYTE* sd = <BYTE*>malloc((length) * sizeof(BYTE))
    GetFileSecurityW(wcharfilename, request, sd, length, &length)
    PyMem_Free(wcharfilename)
    return sd


cdef PSID _get_security_descriptor_owner(PSID sd):
    cdef PSID sid
    cdef BOOL sid_defaulted
    GetSecurityDescriptorOwner(sd, &sid, &sid_defaulted)
    return (sid)


cdef _look_up_account_sid(PSID sid):
    cdef int SIZE = 256
    cdef wchar_t* name = <wchar_t*>malloc((SIZE) * sizeof(wchar_t))
    cdef wchar_t* domain = <wchar_t*>malloc((SIZE) * sizeof(wchar_t))
    cdef DWORD cch_name = SIZE
    cdef DWORD cch_domain = SIZE
    cdef _SID_NAME_USE sid_type

    cdef BOOL ret = LookupAccountSidW(NULL, sid, name, &cch_name, domain, &cch_domain, &sid_type)
    if ret == 0:
        lasterror = GetLastError()
        if lasterror == ERROR_NONE_MAPPED:
            # Unknown (removed?) user or file from another windows installation
            free(name)
            free(domain)
            return 'unknown', 'unknown', 0
        else:
            raise_error('LookupAccountSidW')

    pystrName = PyUnicode_FromWideChar(name, -1)
    pystrDomain = PyUnicode_FromWideChar(domain, -1)

    free(name)
    free(domain)
    return pystrName, pystrDomain, <unsigned int>sid_type


cdef sid2string(PSID sid):
    cdef wchar_t* sidstr
    ConvertSidToStringSidW(sid, &sidstr)
    ret = PyUnicode_FromWideChar(sidstr, -1)
    LocalFree(<HLOCAL>sidstr)
    return ret


def get_owner(path):
    cdef BYTE* sd = _get_file_security(path, OWNER_SECURITY_INFORMATION)
    if sd == NULL:
        return 'unknown', 'S-1-0-0'
    cdef PSID sid = _get_security_descriptor_owner(sd)
    if sid == NULL:
        return 'unknown', 'S-1-0-0'
    name, domain, sid_type = _look_up_account_sid(sid)
    sidstr = sid2string(sid)
    free(sd)
    if domain and domain.lower() != platform.node().lower() and domain != 'BUILTIN':
        return '{0}\\{1}'.format(domain, name), sidstr
    else:
        return name, sidstr


def set_owner(path, owner, sidstring = None):
    cdef PSID newsid
    cdef wchar_t* temp
    cdef _SID_NAME_USE sid_type
    cdef DWORD length = 0
    cdef DWORD domainlength = 0
    if sidstring is not None:
        temp = PyUnicode_AsWideCharString(sidstring, NULL)
        ConvertStringSidToSidW(temp, &newsid)
    if sidstring is None or GetLastError() == ERROR_INVALID_SID:
        temp = PyUnicode_AsWideCharString(owner, NULL)

        LookupAccountNameW(NULL, temp, NULL, &length, NULL, &domainlength, &sid_type)

        newsid = <PSID>malloc((length) * sizeof(BYTE))
        SetLastError(0)
        domainlength = 0
        LookupAccountNameW(NULL, temp, newsid, &length, NULL, &domainlength, &sid_type)
        if GetLastError() != 0:
            raise_error('LookupAccountNameW', owner)
            PyMem_Free(temp)
            return

    PyMem_Free(temp)

    cdef wchar_t* cstrPath = PyUnicode_AsWideCharString(path, NULL)
    SetNamedSecurityInfoW(cstrPath, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, newsid, NULL, NULL, NULL)
    PyMem_Free(cstrPath)
    if length == 0:
        LocalFree(<HLOCAL>newsid)
    else:
        free(newsid)


def acl_get(path, item, st, numeric_owner=False, depth = 0):
    if not permissions_enabled:
        enable_permissions()
    pyDACL = []
    pySACL = []
    if not os.path.samefile(os.path.abspath(path), os.path.abspath(os.path.join(path, ".."))):
        pyDACL, pySACL = acl_get(os.path.abspath(os.path.join(path, "..")), item, st, numeric_owner, depth + 1)

    cdef int request = DACL_SECURITY_INFORMATION
    if permissions_granted:
        request = DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION
    cdef BYTE* SD = _get_file_security(path, request)
    if SD == NULL:
        return

    cdef uint32_t dacllength
    cdef _EXPLICIT_ACCESS_W* DACL
    cdef uint32_t sacllength
    cdef _EXPLICIT_ACCESS_W* SACL

    # LookupSecurityDescriptorPartsW(&owner, &group, &dacllength, &DACL, &sacllength, &sacl, SD)
    LookupSecurityDescriptorPartsW(NULL, NULL, &dacllength, &DACL, &sacllength, &SACL, SD)

    cdef PSID newsid
    cdef uint32_t domainlength
    cdef uint32_t sidlength
    cdef _SID_NAME_USE sid_type

    # DACL
    for i in range(dacllength):
        permissions = None
        name = ""
        sidstr = ""
        if DACL[i].Trustee.TrusteeForm == TRUSTEE_IS_SID:
            name, domain, type = _look_up_account_sid(<BYTE*>(DACL[i].Trustee.ptstrName))
            sidstr = sid2string(<PSID>(DACL[i].Trustee.ptstrName))

        elif DACL[i].Trustee.TrusteeForm == TRUSTEE_IS_NAME:
            sid_type = SidTypeInvalid
            domainlength = 0
            LookupAccountNameW(NULL, DACL[i].Trustee.ptstrName, NULL, &sidlength, NULL, &domainlength, &sid_type)

            newsid = <PSID>malloc((sidlength) * sizeof(BYTE))
            domainlength = 0
            LookupAccountNameW(NULL, DACL[i].Trustee.ptstrName, newsid, &sidlength, NULL, &domainlength, &sid_type)
            trusteeName, domain, type = _look_up_account_sid(newsid)

            name = trusteeName
            sidstr = sid2string(newsid)
            free(newsid)

        elif DACL[i].Trustee.TrusteeForm == TRUSTEE_BAD_FORM:
            continue
        if ((depth == 0 and DACL[i].grfInheritance & INHERIT_ONLY != 0)
            or (DACL[i].grfInheritance & INHERIT_NO_PROPAGATE and depth == 1)
            or (DACL[i].grfInheritance != NO_INHERITANCE and DACL[i].grfInheritance & INHERIT_NO_PROPAGATE == 0)):
            permissions = {'user': {'name': name, 'sid': sidstr}, 'permissions': (DACL[i].grfAccessPermissions, DACL[i].grfAccessMode, NO_INHERITANCE)}
            pyDACL.append(permissions)

    if permissions_granted:
        for i in range(sacllength):
            permissions = None
            name = ""
            sidstr = ""
            if DACL[i].Trustee.TrusteeForm == TRUSTEE_IS_SID:
                name, domain, type = _look_up_account_sid(<BYTE*>(SACL[i].Trustee.ptstrName))
                sidstr = sid2string(<PSID>(SACL[i].Trustee.ptstrName))

            elif SACL[i].Trustee.TrusteeForm == TRUSTEE_IS_NAME:
                sid_type = SidTypeInvalid
                domainlength = 0
                LookupAccountNameW(NULL, SACL[i].Trustee.ptstrName, NULL, &sidlength, NULL, &domainlength, &sid_type)

                newsid = <PSID>malloc((sidlength) * sizeof(BYTE))
                domainlength = 0
                LookupAccountNameW(NULL, SACL[i].Trustee.ptstrName, newsid, &sidlength, NULL, &domainlength, &sid_type)
                trusteeName, domain, type = _look_up_account_sid(newsid)

                name = trusteeName
                sidstr = sid2string(newsid)
                free(newsid)
            else:
                continue
            if ((depth == 0 and SACL[i].grfInheritance & INHERIT_ONLY != 0)
                or (SACL[i].grfInheritance & INHERIT_NO_PROPAGATE and depth == 1)
                or (SACL[i].grfInheritance != NO_INHERITANCE and SACL[i].grfInheritance & INHERIT_NO_PROPAGATE == 0)):
                permissions = {'user': {'name': name, 'sid': sidstr}, 'permissions': (SACL[i].grfAccessPermissions, SACL[i].grfAccessMode, NO_INHERITANCE)}
                pySACL.append(permissions)

    if depth == 0:
        item['win_dacl'] = json.dumps(pyDACL)
        item['win_sacl'] = json.dumps(pySACL)

    free(SD)
    LocalFree(<HLOCAL>DACL)
    LocalFree(<HLOCAL>SACL)
    return pyDACL,pySACL


def acl_set(path, item, numeric_owner=False):
    if not permissions_enabled:
        enable_permissions()

    cdef _EXPLICIT_ACCESS_W* DACL
    cdef wchar_t* temp
    cdef PSID newsid
    cdef _ACL* newDACL

    cdef wchar_t* cstrPath

    if 'win_dacl' in item:
        pyDACL = json.loads(item.win_dacl)
        if len(pyDACL) > 0:
            DACL = <_EXPLICIT_ACCESS_W*>calloc(sizeof(_EXPLICIT_ACCESS_W), len(pyDACL))

            for i in range(len(pyDACL)):
                if pyDACL[i]['user']['name'] == '' or numeric_owner:
                    DACL[i].Trustee.TrusteeForm = TRUSTEE_IS_SID
                    temp = PyUnicode_AsWideCharString(pyDACL[i]['user']['sid'], NULL)
                    ConvertStringSidToSidW(temp, &newsid)
                    DACL[i].Trustee.ptstrName = <LPCTSTR>newsid
                    PyMem_Free(temp)
                else:
                    DACL[i].Trustee.TrusteeForm = TRUSTEE_IS_NAME
                    DACL[i].Trustee.ptstrName = PyUnicode_AsWideCharString(pyDACL[i]['user']['name'], NULL)
                DACL[i].grfAccessPermissions = pyDACL[i]['permissions'][0]
                DACL[i].grfAccessMode = pyDACL[i]['permissions'][1]
                DACL[i].grfInheritance = pyDACL[i]['permissions'][2]

            SetEntriesInAclW(len(pyDACL), DACL, NULL, &newDACL)
            cstrPath = PyUnicode_AsWideCharString(path, NULL)
            SetNamedSecurityInfoW(cstrPath, SE_FILE_OBJECT, PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, newDACL, NULL)

            for i in range(len(pyDACL)):
                if pyDACL[i]['user']['name'] == '' or numeric_owner:
                    LocalFree(<HLOCAL>DACL[i].Trustee.ptstrName)
                else:
                    PyMem_Free(DACL[i].Trustee.ptstrName)
            free(DACL)
            PyMem_Free(cstrPath)
            LocalFree(<HLOCAL>newDACL)

    cdef _EXPLICIT_ACCESS_W* SACL
    cdef _ACL* newSACL
    if permissions_granted and 'win_sacl' in item:
        pySACL = json.loads(item.win_sacl)
        if len(pySACL) > 0:
            SACL = <_EXPLICIT_ACCESS_W*>calloc(sizeof(_EXPLICIT_ACCESS_W), len(pySACL))

            for i in range(len(pyDACL)):
                if pySACL[i]['user']['name'] == '' or numeric_owner:
                    SACL[i].Trustee.TrusteeForm = TRUSTEE_IS_SID
                    temp = PyUnicode_AsWideCharString(pySACL[i]['user']['sid'], NULL)
                    ConvertStringSidToSidW(temp, &newsid)
                    SACL[i].Trustee.ptstrName = <LPCTSTR>newsid
                    PyMem_Free(temp)
                else:
                    SACL[i].Trustee.TrusteeForm = TRUSTEE_IS_NAME
                    SACL[i].Trustee.ptstrName = PyUnicode_AsWideCharString(pySACL[i]['user']['name'], NULL)
                SACL[i].grfAccessPermissions = pySACL[i]['permissions'][0]
                SACL[i].grfAccessMode = pySACL[i]['permissions'][1]
                SACL[i].grfInheritance = pySACL[i]['permissions'][2]

            SetEntriesInAclW(len(pySACL), SACL, NULL, &newSACL)
            cstrPath = PyUnicode_AsWideCharString(path, NULL)
            SetNamedSecurityInfoW(cstrPath, SE_FILE_OBJECT, PROTECTED_SACL_SECURITY_INFORMATION, NULL, NULL, newSACL, NULL)

            for i in range(len(pySACL)):
                if pySACL[i]['user']['name'] == '' or numeric_owner:
                    LocalFree(<HLOCAL>SACL[i].Trustee.ptstrName)
                else:
                    PyMem_Free(SACL[i].Trustee.ptstrName)
            free(SACL)
            PyMem_Free(cstrPath)
            LocalFree(<HLOCAL>newSACL)


def sync_dir(path):
    # TODO
    pass


def get_ads(path):
    ret = []
    cdef _WIN32_FIND_STREAM_DATA data
    cdef wchar_t* cstrPath = PyUnicode_AsWideCharString(path, NULL)
    cdef HANDLE searchHandle = FindFirstStreamW(cstrPath, FindStreamInfoStandard, <void*>&data, 0)
    if searchHandle == <HANDLE>INVALID_HANDLE_VALUE:
        PyMem_Free(cstrPath)
        return []
    ret.append(PyUnicode_FromWideChar(data.cStreamName, -1))
    while FindNextStreamW(searchHandle, <void*>&data) != 0:
        ret.append(PyUnicode_FromWideChar(data.cStreamName, -1))
    errno = GetLastError()
    if errno != ERROR_HANDLE_EOF:
        raise_error('FindNextStreamW', path)

    FindClose(searchHandle)
    PyMem_Free(cstrPath)
    return ret


def select(rlist, wlist, xlist, timeout=0):
    retRlist = []
    retXlist = []
    for pipe in rlist:
        size = ctypes.wintypes.DWORD(0)
        if not PeekNamedPipe(msvcrt.get_osfhandle(pipe), None, 0, None, ctypes.byref(size), None):
            if size.value == 0 and pipe in xlist:
                retXlist.append(pipe)
        if size.value > 0:
            retRlist.append(pipe)
    return retRlist, wlist, retXlist
