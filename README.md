<h1 align="center"> Process-Injection </h1>

<p align="center">Selection ➡️ Allocation  ➡️  Injection ➡️  Execution</p>

--------------------------------------------------------------------------------------------------------




```
> ChatGPT, list different injection techniques, and rate them top to bottom
```
<br>

| Difficulty   | Technique                   | Description                                                                 |
---------------|-----------------------------|-----------------------------------------------------------------------------|
| Basic        |✅ DLL Injection            | DLL injected into a target process using standard OS functions              |
|              |✅ Shellcode Injection      | Shellcode written into another process, executed via new thread             |
| Intermediate | Process Hollowing           | Start legit process, remove its memory, replace with malicious PE file      |
|              |✅ APC Injection               | Queue malicious code to run when a thread enters an alertable state         |
|              |✅ Thread Hijacking            | Suspends an existing thread, and re-directs execution                       | 
| Advanced     | Reflective DLL Injection    | Loads a DLL directly from memory without touching disk                      |
|              | Manual Mapping              | Fully custom loading of a module into memory (no OS loader)                 |
|              | Process Doppelganging       | Use NTFS transaction features to run code from a legit-looking process image|
| Expert       | Process Ghosting            | Similar to Doppelganging, but uses deleted files still mapped in memory     |
|              |✅ Early Bird Injection        | Inject code before the main thread of a process starts executing            |
|              | Kernel Assisted Injection   | Uses kernel drivers to inject or malipulate processes                       |

<br>

**Note on table:** Difficulty, is in terms of stealthiness and ability of a given technique to evade detection
- Difficulty is **NOT** in terms of coding complexity, ie

<br>

<ins>Process Hollowing (Intermediate)</ins>
- hundreds of lines of code, requiring the following:
- manual parsing of PE-payload based on known pointer offsets and field values
- padding CONTEXT64 struct to ensure correct struct memory-size, and registers at correct offsets
- taking snapshot of CPU registers and ensuring Rip and Rsp are perfectly aligned on 16-byte memory boundaries
- fixing IAT...
- too many hacks required to get things perfectly aligned in memory 🫠

<ins>Early Bird Injection (Expert)</ins>
- just another variant of APC injection 
- barebones < 100 lines, quick and very easy to implement

--------------------------------------------------------------------------------------------------------

Classifying various PI methods is typically based on the Execution technique, though not always so obvious. As such trying to place different techniques/methods can be difficult, as each stage has numerous techniques that can be mixed and matched in various combinations.


**Waiting Thread Hijacking via Module Stomping**

- Allocation -> Module Stomping
- Injection -> WriteProcessMemory()
- Execution -> Waiting Thread Hijacking

**Classic DLL injection**

- Allocation -> VirtualAllocEx()
- Injection -> LoadLibraryW()
- Execution -> CreateRemoteThread()



