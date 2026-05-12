<h1 align="center"> Process Hollowing </h1>


Summary:
- 
A target process launched in a SUSPENDED state, and its code is replaced with a malicious payload (PE file). 
Process execution is then resumed, allowing the payload to run under the identity of the target process (eg notepad.exe)

Steps:
-
This technique requires that the injector (eg python) act as the Windows Loader, as we are loading a full PE file, and all dependency requirements must be met.



<br><h5 align="center"> [SELECTION] </h5>

1) **Create SUSPENDED process:** ```CreateProcessW()```
- ```CreateProcess()``` called with the ```CREATE_SUSPENDED``` flag (```0x04```) to spawn a target process (eg notepad.exe)
- whilst the process is loaded, its primary thread does not yet execute any instructions



<br><h5 align="center"> [ALLOCATION] </h5>

2) **Unmap Memory (Hollowing):** ```NtUnmapViewOfSection()```
- the original executable image is removed/un-mapped from the virtual address space of the target process
- this  "hollows out" the process, leaving its memory ready for the payload

<br>
<br>

3) **Allocate Memory:** ```VirtualAllocEx()```
- reserve and commit memory space in the target process, large enough to contain the payload

<br>

&emsp;**Note:** ```VirtualAllocEx()``` allows you to request a specific address to reserve.

&emsp;Here we have three options, each requiring different FIXES be applied (_see below_):

- ```ImageBase``` (or Preferred Base Address) of the payload. This is the address the payload 'prefers' to be loaded at in virtual memory. Its value is stored in the ```Optional Header``` of the PE file itself, and is typically ```0x140000000``` for x64 PEs. _**Fix Required:** PEB patching_

- ```ModuleBaseAddress``` This is the starting point of where the executable image (eg notepad.exe), is loaded within the process' virtual memory. _**Fix Required:** Base Relocations (if ```ModuleBaseAddress``` != ```ImageBase```)_

- Random address chosen by ```VirtualAllocEx()```. This can be on purpose, where consciously pass ```0``` as the second argument in the function call. Or the requested address is already taken, and another randomly available address is returnend. _**Fix Required:** Base Relocations AND PEB Patching_



<br><h5 align="center"> [INJECTION] </h5>


4) **Write Payload:** ```WriteProcessMemory()```

- payload is written into the space allocated by ```VirtualAllocEx()```
- as a compiled PE is injected, it must be manually parsed and its components mapped to their relevant addresses in virtual memory
- this is due to how a PE, as it exists on-disk, is different to how it exists in-memory (ie, VirtualSize > SizeOfRawData)
- headers are written first, then followed by the different sections in the ```Section Table```  (eg ```.text```, ```.data```, etc)
- where each section contains a ```VirtualAddress```, which is added to the ```Actual Base Address``` (```ImageBase```, or ```ModuleBaseAddress```) to determine its absolute location in memory


<br><h5 align="center"> _**APPLY FIXES**_ </h5>

The following fixes are necessary because, in Process Hollowing, we are manually performing the role of the Windows loader
- need to ensure the payload's internal pointers, external dependencies, and OS-level metadata are correctly aligned with its new location in memory
- without these fixes, the process will immediately crash upon resumption

<br>
<br>

5) **PEB Patching:**
- the Process Environment Block, <description>
The PEB in the target process is updated to reflect the new malicious base address. This ensures that internal OS functions see the malicious image as the "official" loaded module.

6) **Base Relocations:**
- if the payload cannot be mapped at its preferred base address (the address it was compiled to expect)
- the PE's relocation table must be parsed, and manually adjust absolute memory addresses to match the new location

7) **IAT (Import Address Table) Fixing:**
- The attacker resolves the addresses of required system functions (like CreateFile or Sleep) and populates the payload's IAT so it can correctly call external libraries (DLLs).

8) **Update Thread Context:**
- Use GetThreadContext to retrieve the current state of the suspended thread and SetThreadContext to change the Instruction Pointer (EIP/RIP) to the entry point of the malicious payload.


<br><h5 align="center"> [EXECUTION] </h5>

9) **Resume Thread:** ```ResumeThread()```
- ```ResumeThread()``` is called, the target process "wakes up" and executes the injected payload


Applied Fixes - In Depth
- 

af
