# Process-Injection
_Pushing the limits of brain to not explode_

```
Hey ChatGPT, list different injection techniques, and rate them top to bottom
```

| Difficulty   | Technique                   | Description                                                                 |
---------------|-----------------------------|-----------------------------------------------------------------------------|
| Basic        | DLL Injection               | Injects a DLL into a target process using standard OS functions             |
|              | Remote Thread Injection     | Writes code into another process and executes via new thread                |
| Intermediate | Process Hollowing           | Start legit process, remove its memory, replace with malicious code         |
|              | APC Injection               | Queue malicious code to run when a thread enters an alertable state         |
|              | Thread Hijacking            | Suspends an existing thread, and re-directs execution                       | 
| Advanced     | Reflective DLL Injection    | Loads a DLL directly from memory without touching disk                      |
|              | Manual Mapping              | Fully custom loading of a module into memory (no OS loader)                 |
|              | Process Doppelganging       | Use NTFS transaction features to run code from a legit-looking process image|
| Expert       | Process Ghosting            | Similar to Doppelganging, but uses deleted files still mapped in memory     |
|              | Early Bird Injection        | Inject code before the main thread of a process starts executing            |
|              | Kernel Assisted Injection   | Uses kernel drivers to inject or malipulate processes                       |
