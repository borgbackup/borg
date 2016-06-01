#cython: language_level=3

import json
import os.path
from libc.stddef cimport wchar_t
from libc.stdint cimport uint16_t, uint32_t, uint64_t
cimport cpython.array
import array

import platform
from ..helpers import safe_decode, safe_encode

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
    struct _ACL:
        uint16_t AceCount

    HLOCAL LocalFree(HLOCAL)
    DWORD GetLastError();
    void SetLastError(DWORD)

    DWORD FormatMessageW(DWORD, void*, DWORD, DWORD, wchar_t**, DWORD, void*)


    BOOL InitializeSecurityDescriptor(BYTE*, DWORD)

    BOOL LookupAccountNameW(LPCTSTR, LPCTSTR, PSID, LPDWORD, LPCTSTR, LPDWORD, LPDWORD)
    BOOL GetSecurityDescriptorDacl(PSID, BOOL*, _ACL**, BOOL*)

    cdef extern int ERROR_INSUFFICIENT_BUFFER
    cdef extern int ERROR_INVALID_SID
    cdef extern int ERROR_NONE_MAPPED

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

    DWORD GetExplicitEntriesFromAclW(_ACL*, uint32_t*, _EXPLICIT_ACCESS_W**)


cdef extern from 'Sddl.h':
    ctypedef int* LPBOOL

    BOOL GetFileSecurityW(LPCTSTR, int, PSID, DWORD, LPDWORD)
    BOOL GetSecurityDescriptorOwner(PSID, PSID*, LPBOOL)
    BOOL LookupAccountSidW(LPCTSTR, PSID, LPCTSTR, LPDWORD, LPCTSTR, LPDWORD, uint16_t*)
    BOOL ConvertSidToStringSidW(PSID, LPCTSTR*)
    BOOL ConvertStringSidToSidW(LPCTSTR, PSID*)
    BOOL ConvertSecurityDescriptorToStringSecurityDescriptorW(BYTE*, DWORD, int, LPCTSTR*, int*)

    cdef extern int SDDL_REVISION_1


cdef extern from 'Aclapi.h':
    ctypedef void* PACL
    DWORD GetNamedSecurityInfoW(LPCTSTR, SE_OBJECT_TYPE, DWORD, PSID*, PSID*, PACL*, PACL*, _ACL**)
    DWORD SetNamedSecurityInfoW(LPCTSTR, int, int, PSID, PSID, PACL, PACL)
    DWORD SetEntriesInAclW(unsigned int, _EXPLICIT_ACCESS_W*, PACL, _ACL**)


def raise_error(api, path=''):
    cdef wchar_t *error_message
    error = GetLastError()
    if not error:
        return
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, error, 0, &error_message, 0, NULL)
    error_string = PyUnicode_FromWideChar(error_message, -1)
    LocalFree(<HLOCAL>error_message)
    error_string = api + ': ' + error_string
    if path:
        raise OSError(error, error_string, path)
    else:
        raise OSError(error, error_string)


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
    cdef uint16_t sid_type = <uint16_t>0

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
    cdef int request = OWNER_SECURITY_INFORMATION
    cdef BYTE* sd = _get_file_security(path, request)
    if sd == NULL:
        return 'unknown', 'S-1-0-0'
    cdef PSID sid = _get_security_descriptor_owner(sd)
    if sid == NULL:
        return 'unknown', 'S-1-0-0'
    name, domain, sid_type = _look_up_account_sid(sid)
    free(sd)
    if domain and domain.lower() != platform.node().lower() and domain != 'BUILTIN':
        return '{0}\\{1}'.format(domain, name), sid2string(sid)
    else:
        return name, sid2string(sid)


def set_owner(path, owner, sidstring = None):
    cdef PSID newsid
    cdef wchar_t* temp
    cdef DWORD sid_type = 0
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


def acl_get(path, item, st, numeric_owner=False):
    cdef int request = DACL_SECURITY_INFORMATION

    cdef BYTE* SD = _get_file_security(path, request)
    if SD == NULL:
        return

    cdef BOOL daclFound
    cdef _ACL* DACL
    cdef BOOL DACLDefaulted
    GetSecurityDescriptorDacl(SD, &daclFound, &DACL, &DACLDefaulted)

    cdef uint32_t length
    cdef _EXPLICIT_ACCESS_W* ACEs

    GetExplicitEntriesFromAclW(DACL, &length, &ACEs)

    pyDACL = []
    cdef PSID newsid
    cdef uint32_t domainlength
    cdef uint32_t sid_type
    for i in range(length):
        permissions = None
        name = ""
        sidstr = ""
        if ACEs[i].Trustee.TrusteeForm == TRUSTEE_IS_SID:
            name, domain, type = _look_up_account_sid(<BYTE*>(ACEs[i].Trustee.ptstrName))
            sidstr = sid2string(<PSID>(ACEs[i].Trustee.ptstrName))

        elif ACEs[i].Trustee.TrusteeForm == TRUSTEE_IS_NAME:
            sid_type = 0
            domainlength = 0
            LookupAccountNameW(NULL, ACEs[i].Trustee.ptstrName, NULL, &(length), NULL, &domainlength, &sid_type)

            newsid = <PSID>malloc((length) * sizeof(BYTE))
            domainlength = 0
            LookupAccountNameW(NULL, ACEs[i].Trustee.ptstrName, newsid, &length, NULL, &domainlength, &sid_type)
            trusteeName, domain, type = _look_up_account_sid(newsid)

            name = trusteeName
            sidstr = sid2string(newsid)
            free(newsid)

        elif ACEs[i].Trustee.TrusteeForm == TRUSTEE_BAD_FORM:
            continue
        permissions = {'user': {'name': name, 'sid': sidstr}, 'permissions': (ACEs[i].grfAccessPermissions, ACEs[i].grfAccessMode, ACEs[i].grfInheritance)}
        pyDACL.append(permissions)
    item[b'win_dacl'] = safe_encode(json.dumps(pyDACL))

    free(SD)
    LocalFree(<HLOCAL>ACEs)


def acl_set(path, item, numeric_owner=False):
    if b'win_dacl' not in item:
        return

    pyDACL = json.loads(safe_decode(item[b'win_dacl']))
    cdef _EXPLICIT_ACCESS_W* ACEs = <_EXPLICIT_ACCESS_W*>calloc(sizeof(_EXPLICIT_ACCESS_W), len(pyDACL))
    cdef wchar_t* temp
    cdef PSID newsid
    for i in range(len(pyDACL)):
        if pyDACL[i]['user']['name'] == '' or numeric_owner:
            ACEs[i].Trustee.TrusteeForm = TRUSTEE_IS_SID
            temp = PyUnicode_AsWideCharString(pyDACL[i]['user']['sid'], NULL)
            ConvertStringSidToSidW(temp, &newsid)
            ACEs[i].Trustee.ptstrName = <LPCTSTR>newsid
            PyMem_Free(temp)
        else:
            ACEs[i].Trustee.TrusteeForm = TRUSTEE_IS_NAME
            ACEs[i].Trustee.ptstrName = PyUnicode_AsWideCharString(pyDACL[i]['user']['name'], NULL)
        ACEs[i].grfAccessPermissions = pyDACL[i]['permissions'][0]
        ACEs[i].grfAccessMode = pyDACL[i]['permissions'][1]
        ACEs[i].grfInheritance = pyDACL[i]['permissions'][2]
    cdef _ACL* newDACL
    SetEntriesInAclW(len(pyDACL), ACEs, NULL, &newDACL)
    cdef wchar_t* cstrPath = PyUnicode_AsWideCharString(path, NULL)
    SetNamedSecurityInfoW(cstrPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, newDACL, NULL)

    for i in range(len(pyDACL)):
        if pyDACL[i]['user']['name'] == '' or numeric_owner:
            LocalFree(<HLOCAL>ACEs[i].Trustee.ptstrName)
        else:
            PyMem_Free(ACEs[i].Trustee.ptstrName)
    free(ACEs)
    PyMem_Free(cstrPath)
    LocalFree(<HLOCAL>newDACL)


def sync_dir(path):
    # TODO
    pass

