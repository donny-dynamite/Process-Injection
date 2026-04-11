# Process-Injection
_Pushing the limits of the mind to not implode_

```
Hey ChatGPT, list different injection techniques, and rate them top to bottom
```

| Difficulty   | Technique                   | Description                                                                 |
---------------|-----------------------------|-----------------------------------------------------------------------------|
| Basic        | DLL Injection               | DLL injected into a target process using standard OS functions              |
|              | Shellcode Injection         | Shellcode written into another process, executed via new thread             |
| Intermediate | Process Hollowing           | Start legit process, remove its memory, replace with malicious code         |
|              | APC Injection               | Queue malicious code to run when a thread enters an alertable state         |
|              | Thread Hijacking            | Suspends an existing thread, and re-directs execution                       | 
| Advanced     | Reflective DLL Injection    | Loads a DLL directly from memory without touching disk                      |
|              | Manual Mapping              | Fully custom loading of a module into memory (no OS loader)                 |
|              | Process Doppelganging       | Use NTFS transaction features to run code from a legit-looking process image|
| Expert       | Process Ghosting            | Similar to Doppelganging, but uses deleted files still mapped in memory     |
|              | Early Bird Injection        | Inject code before the main thread of a process starts executing            |
|              | Kernel Assisted Injection   | Uses kernel drivers to inject or malipulate processes                       |
