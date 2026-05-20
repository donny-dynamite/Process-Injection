<h1 align="center"> Process Injection </h1>

<p align="center">Selection ➡️ Allocation  ➡️  Injection ➡️  Execution</p>

--------------------------------------------------------------------------------------------------------




```
> Google AI, list different injection techniques, and rate them top to bottom
```

<br>

| Generation         | Difficulty    | Technique                    | Description                                                                   |
|--------------------|---------------|------------------------------|-------------------------------------------------------------------------------|
| 1) Traditional     |  Basic        |✅ DLL Injection              | DLL injected into a target process using standard OS functions               |
|                    |               |✅ Shellcode Injection        | Shellcode written into another process, executed via new thread              |
| 2) Hijacking       |  Intermediate |✅ Process Hollowing          | Start legit process, unmap (hollow-out) its memory, replace with malicious PE file      |
|                    |               |✅ Thread Hijacking           | Suspends an existing thread, and re-directs execution                       | 
|                    |               |✅ APC Injection              | Queue malicious code to run when a thread enters an alertable state         |
|                    |               |✅ Early Bird Injection       | Inject code before the main thread of a process starts executing            |
| 3) Fileless        | Advanced      | Reflective DLL Injection     | Loads a DLL directly from memory without touching disk                      |
|                    |               |✅ Manual Mapping            | Fully custom loading of a module into memory (no OS loader)                 |
| 4) Evasive         | Expert        | Atom Bombing                 | Payload written to Global Atom Table, execution via APC                      |
|                    |               | Process Doppelganging        | Use NTFS transaction features to run code from a legit-looking process image |
|                    |               | Process Ghosting             | Similar to Doppelganging, but uses deleted files still mapped in memory      |
|                    |               | Process Herpaderping         | Modifies on-disk payload, after written to memory, but _before_ execution    |
|                    |               | Threadless Injection/Hooking | Hijack function calls within a target process, entry points -> jmp to payload  |
| 5) Kernel          | Adv. Expert   |Kernel Assisted Injection   | Uses kernel drivers to inject or malipulate processes                       |      
<br>

**Note on table:** Difficulty reflects Evasion & Stealth Capability (how hard it is for security tools to detect). It does **NOT** reflect implementation complexity, for example:

<br>

<ins>Process Hollowing (Intermediate)</ins>
- high engineering overhead required -> hundreds (thousand+) of lines of code 🫠
- manual PE payload parsing, based on known pointer offsets and field values, ensuring file sections are written to their correct memory address

Additionally ensuring following patches are applied:
- patching PEB to ensure OS-metadata is correct
- patching Base Relocation Table to ensure all memory pointers refer to correct address space
- patching Import Address Table for required loading of DLL modules
- updating Thread Context, to ensure correct memory/offset alignment, as well as updating CPU register pointers

<ins>Early Bird Injection (Expert)</ins>
- just another variant of APC injection 
- barebones < 100 lines, quick and very easy to implement

--------------------------------------------------------------------------------------------------------
<br><h2 align="center"> **A note on variable naming conventions** </h2>


Here we are constantly juggling between **three** different types of addressing, and it can be very confusing to determine which is being referred to. As such, the variable name _suffix_ will determine address type:

<br>
<br>

1) File Offsets (Raw Offsets):
- variable names will end in ```offset``` -> ```get_pe_header_offset()```
- this is the physical location of data, within a PE file, when the executable is on-disk

<br>

File Offsets are generally universally relative to the **beginning** of the PE. However there are times when parsing, that an offset will be relative to a section (Section Offset). In these instances:
- variable names will end in ```_so``` -> ```reloc_so = reloc_va - reloc_data_va```

<br>
<br>

2) Relative Virtual Addresses (RVA):
- variable names will end in ```rva``` -> ```entry_point_rva```
- this is an **offset**, relative to where the image eventually gets loaded in virtual memory
- where the image is loaded is called the ```Actual Base Address``` (as returned by ```VirtualAllocEx()```)

Within a PE file, there is an ```AddressOfEntryPoint``` -> ```OptionalHeader```
- this is the ```entry_point_rva```, or offset of where the entry point of the payload will exist in virtual memory
- this is an offset (vs an absolute address), because the compiler cannot predict where the OS will map the executable at runtime due to ASLR and memory layout availability
- the ```RVA``` (offset), is used to calculate the eventual absolute ```Virtual Address``` (see below) of where data should exist in memory

<br>
<br>

3) Virtual Addresses (VA):
- variable names will end in ```va``` -> ```actual_entry_point_va```
- the ```Virtual Address``` is the **absolute/actual** address in virtual memory, where data is located
- in terms of a payload, the ```actual_entry_point_va``` =  ```actual_base_address_va``` + ```entry_point_rva```

<br><h3 align="center"> **If absolutely none of this makes sense:** </h3>

- I honestly recommend sticking to the various Thread Injection Techniques
- once you fully understand those, then take a look at Process Hollowing
- when you have understood Process Hollowing...
- **go over it again...**
- two-dozen times...
- until you start dreaming about it...
- this is not a joke...
--------------------------------------------------------------------------------------------------------

