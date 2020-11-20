# CodeInjection-windows

## Some Key Functions
### OpenProcess()
HANDLE OpenProcess(
  DWORD dwDesiredAccess,  // access flag
  BOOL bInheritHandle,    // handle inheritance option
  DWORD dwProcessId       // process identifier
);

### VirtualAllocEx()
LPVOID VirtualAllocEx(
  HANDLE hProcess,          // process to allocate memory
  LPVOID lpAddress,         // desired starting address 
  SIZE_T dwSize,            // size of region to allocate
  DWORD flAllocationType,   // type of allocation
  DWORD flProtect           // type of access protection
);

### WriteProcessMemory()
BOOL WriteProcessMemory(
  HANDLE hProcess,                // handle to process
  LPVOID lpBaseAddress,           // base of memory area
  LPCVOID lpBuffer,               // data buffer
  SIZE_T nSize,                   // count of bytes to write
  SIZE_T * lpNumberOfBytesWritten // count of bytes written
);

### CreateRemoteThread()
**Evil Function**
HANDLE CreateRemoteThread(
  HANDLE hProcess,                          // handle to process
  LPSECURITY_ATTRIBUTES lpThreadAttributes, // SD
  SIZE_T dwStackSize,                       // initial stack size
  LPTHREAD_START_ROUTINE lpStartAddress,    // thread function
  LPVOID lpParameter,                       // thread argument
  DWORD dwCreationFlags,                    // creation option
  LPDWORD lpThreadId                        // thread identifier
);

## Some Key Steps
1. Choose a victim process
2. Get Process Handle by OpenProcess()
3. Allocate memory in the target process by VirtualAllocEx()
4. Write the code into the memory allocated in step 3
5. CreateRemoteThread()


