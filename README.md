# CodeInjection-windows

## Some Key Functions
### OpenProcess()
HANDLE OpenProcess(<br>
DWORD dwDesiredAccess,  // access flag<br>
BOOL bInheritHandle,    // handle inheritance option<br>
DWORD dwProcessId       // process identifier<br>
);

### VirtualAllocEx()
LPVOID VirtualAllocEx(<br>
  HANDLE hProcess,          // process to allocate memory<br>
  LPVOID lpAddress,         // desired starting address <br>
  SIZE_T dwSize,            // size of region to allocate<br>
  DWORD flAllocationType,   // type of allocation<br>
  DWORD flProtect           // type of access protection<br>
);

### WriteProcessMemory()
BOOL WriteProcessMemory(<br>
  HANDLE hProcess,                // handle to process<br>
  LPVOID lpBaseAddress,           // base of memory area<br>
  LPCVOID lpBuffer,               // data buffer<br>
  SIZE_T nSize,                   // count of bytes to write<br>
  SIZE_T * lpNumberOfBytesWritten // count of bytes written<br>
);<br>

### CreateRemoteThread()
**Evil Function**<br>
HANDLE CreateRemoteThread(<br>
  HANDLE hProcess,                          // handle to process<br>
  LPSECURITY_ATTRIBUTES lpThreadAttributes, // SD<br>
  SIZE_T dwStackSize,                       // initial stack size<br>
  LPTHREAD_START_ROUTINE lpStartAddress,    // thread function<br>
  LPVOID lpParameter,                       // thread argument<br>
  DWORD dwCreationFlags,                    // creation option<br>
  LPDWORD lpThreadId                        // thread identifier<br>
);

## Some Key Steps
1. Choose a victim process
2. Get Process Handle by OpenProcess()
3. Allocate memory in the target process by VirtualAllocEx()
4. Write the code into the memory allocated in step 3
5. CreateRemoteThread()


