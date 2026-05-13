<h1 align="center"> Process Hollowing </h1>


Summary:
- 
A target process is launched in a SUSPENDED state, and its code is replaced with another PE file (payload). 
Process execution is then resumed, allowing the payload to run under the identity of the target process (eg ```notepad.exe```)

Steps:
-
This technique requires that the injector (eg python) act as the Windows Loader, as we are loading a full PE file, and all dependency requirements must be met



<br><h5 align="center"> [SELECTION] </h5>

1) **Create SUSPENDED process:** ```CreateProcessW()```
- ```CreateProcess()``` is called with the ```CREATE_SUSPENDED``` flag (```0x04```) to spawn a target process (eg ```notepad.exe```)
- whilst the process is loaded, its primary thread does not yet execute any instructions



<br><h5 align="center"> [ALLOCATION] </h5>

2) **Unmap Memory (Hollowing):** ```NtUnmapViewOfSection()```
- the original executable image (eg ```notepad.exe```) is removed/un-mapped from the virtual address space of the target process
- this  "hollows out" the process, leaving its memory ready for the payload

<br>
<br>

3) **Allocate Memory:** ```VirtualAllocEx()```
- reserve and commit memory space in the target process, large enough to contain the payload

<br>

&emsp;**Note:** ```VirtualAllocEx()``` allows you to request a specific address to reserve.

&emsp;Here we have three options, each requiring different FIXES be applied (_see below_):

- the preferred base address of the payload, ```ImageBase```. This is the address the payload 'prefers' to be loaded at in virtual memory. Its value is hard-coded and found in the ```Optional Header``` of the PE file itself, typically ```0x140000000``` for x64 binaries.

&emsp;_**Fix Required:** PEB patching_

- the Base Address of the target process, ```ImageBaseAddress```. This field is found in the PEB (_see below_) and is the starting virtual memory address where the target executable (eg ```notepad.exe```), was originally loaded by the OS.

&emsp;_**Fix Required:** Base Relocations (if ```ImageBaseAddress``` != ```ImageBase```)_

- random address chosen by ```VirtualAllocEx()```. This can be on purpose, where the value  ```0``` is consciously passed as the second argument of the function call. Or when requesting an address, it may already be taken, so another randomly available address is returned instead.

&emsp;_**Fix Required:** Base Relocations AND PEB Patching_



<br><h5 align="center"> [INJECTION] </h5>


4) **Write Payload:** ```WriteProcessMemory()```

- the payload is written into the space allocated by ```VirtualAllocEx()```
- as a PE file is injected, it must be manually parsed and its components mapped to their relevant addresses in virtual memory
- this is due to how a PE, as it exists on-disk, is different to how it exists in-memory (ie, VirtualSize > SizeOfRawData)
- headers are written first, then followed by the different sections in the ```Section Table```  (eg ```.text```, ```.data```, etc)
- each section contains a ```VirtualAddress``` value, which is added to the ```Actual Base Address``` (```ImageBase``` from the payload, or ```ImageBaseAddress``` from the process) to determine its absolute location in memory


<br><h5 align="center"> _**APPLY FIXES**_ </h5>

The following fixes are necessary because, in Process Hollowing, we are manually performing the role of the Windows loader
- need to ensure the payload's internal pointers (_Base Relocations_), external dependencies (_IAT_), and OS-level metadata (_PEB_) are correctly aligned with its new location in memory
- without these fixes, the process will immediately crash upon resumption

<br>
<br>

5) **PEB Patching:**
- the Process Environment Block (PEB), is a user-mode data structure that is unique and applies to every single process
- it serves as the process' own internal notebook, storing metadata the application and OS loader needs at runtime
- the PEB contains a field called ```ImageBaseAddress```, which is the starting address in virtual memory where the target executable (eg ```notepad.exe```), was originally loaded by the OS
- if ```VirtualAllocEx()``` allocated memory at this address, PEB patching is **not**
 required, otherwise the ```ImageBaseAddress``` needs to be updated with the address returned by ```VirtualAllocEx()```

<br>
<br>

6) **Base Relocations:**
- when a file is compiled, the compiler generates **absolute (fixed)** memory addresses for components such as global variables and string constants
- these are hard-coded in the binary itself and are based on the default preferred ```ImageBase``` address
- if instead the payload is mapped at a different address (eg due to ASLR, or in this case Process Hollowing), these hard-coded absolute addresses will point to incorrect or unallocated memory locations

To address this issue, the compiler creates a ```.reloc``` section within the PE file:
- this is essentially an array of data blocks that map the exact locations of all hard-coded absolute memory addresses within the binary
- all these pointers must be manually adjusted to their new absolute memory addresses in virtual memory

&emsp;**Authors Note:** this is **not** required **if** image loaded at its preferred ```ImageBase```
- in the author's honest/lazy opinion, _PEB patching_ is **much easier** to resolve than _Base Relocations_ and is preferable in most circumstances
- either way, implementation for _Base Relocations_ is included if ever needed

<br>
<br>

7) **IAT Fixing:**
- the Import Address Table (IAT), acts as an address book that an application (eg payload) uses, to locate/execute functions that belong to external libraries (eg, ```MessageBoxW()``` in ```user32.dll```)

The IAT exists in two distinct states, the static **on-disk state**, and the dynamic **in-memory state:**

&emsp;**_On-Disk (Static)_**
- the IAT contains no actual memory addresses, and essentially mirrors the Import Name Table (INT) which is a read-only static lookup table
- the INT contains pointers to ASCII text strings, or ordinal numbers, that represent the _names_ of functions the payload will need (eg, the string ```"VirtualAllocEx"```)
- the INT acts as the permanent reference that the OS loader (or injector) reads, to determine _which_ functions the payload is requesting

&emsp;**_In-Memory (Dynamic)_**
- the state of the IAT changes completely, and its entries are completely over-written
- the original pointers to text strings are now replaced by live, **absolute** virtual memory addresses, that point directly to the functions inside loaded libraries 

<br>

_**The Process Hollowing Problem**_

Normal operation:
- normally, a running process will have a valid, initialised in-memory IAT that contains absolute memory addresses of all the functions it requires
- however as the process was created in a ```SUSPENDED``` state, and the executable image was subsequently unmapped with ```NtUnmapViewOfSection()```, that original IAT of the process is now destroyed

Injected payload:
- the in-memory IAT of the injected payload is initially stale/blank, as it was copied directly from its static, on-disk state (from Step 4)
- therefore, the in-memory IAT of the payload, must be manually patched and updated with the correct absolute memory addresses of all the functions it requires




<br>
<br>

8) **Update Thread Context:** - ```GetThreadContext()``` and ```SetThreadContext()```
- the _Thread Context_ is a snapshot that contains the CPU register-values for a thread, at a specific point in time
- a number of CPU registers will need their values updated, namely the Instruction Pointer ```Rip```, the General Purpose register ```Rcx```, and the Stack Pointer ```Rsp```
- when a process starts in ```SUSPENDED``` state, the Instruction Pointer (```Rip```) actually points to a function inside ```ntdll.dll```
- both ```Rip``` and ```Rcx``` must be updated and synchronised to both point to the  **_entry point_** of the payload (```Actual Base Address``` + ```AddressOfEntryPoint``` offset)




<br><h5 align="center"> [EXECUTION] </h5>

9) **Resume Thread:** ```ResumeThread()```
- ```ResumeThread()``` is called, the target process "wakes up" and executes the injected payload


Applied Fixes - In Depth
-
The following contained detailed steps of how to perform the required fixes

<br><h5> **IAT FIXING** </h5>



&emsp;**Authors Note**: due to creating a process in ```SUSPENDED``` state, there is every likelihood  that a payload will request a function, inside a module that has not yet been  loaded by the bare-bones (eg ```MessageBoxW``` -> ```user32.dll```)
- to address this the **payload itself** must handle the manual initialisation of these subsystems, eg by calling ```GetDesktopWindow()``` early in the payload, this forces the OS to map ```user32.dll``` and prepares the environment for ```MessageBoxA``` to be executed
- it has been the authors experience, that the process being created in a ```SUSPENDED``` state, and the subsequent unmapping/hollowing of the loaded executable image, that trying to use _Classic DLL Injection_ (```CreateRemoteThread()``` -> ```LoadLibraryW()```) to force load missing libraries does not work (_loader lock deadlocks_)
- 

af
