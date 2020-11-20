// CodeInjection.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
typedef struct
{
    DWORD dwCreateAPIAddr;
    LPCSTR lpFileName;                         // file name
    DWORD dwDesiredAccess;                      // access mode
    DWORD dwShareMode;                          // share mode
    LPSECURITY_ATTRIBUTES lpSecurityAttributes; // SD
    DWORD dwCreationDisposition;                // how to create
    DWORD dwFlagsAndAttributes;                 // file attributes
    HANDLE hTemplateFile;                       // handle to template file
}CREATEFILE_PARAM;
// 函数指针
typedef HANDLE(WINAPI* PFN_CreateFile)(
    LPCSTR lpFileName,                         // file name
    DWORD dwDesiredAccess,                      // access mode
    DWORD dwShareMode,                          // share mode
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, // SD
    DWORD dwCreationDisposition,                // how to create
    DWORD dwFlagsAndAttributes,                 // file attributes
    HANDLE hTemplateFile
    );
// 编写要复制到目标进程的函数
DWORD __stdcall CreateFileThreadProc(LPVOID lParam)
{
    CREATEFILE_PARAM* Gcreate = (CREATEFILE_PARAM*)lParam;
    PFN_CreateFile pfnCreateFile;

    pfnCreateFile = (PFN_CreateFile)Gcreate->dwCreateAPIAddr;
    pfnCreateFile(
        Gcreate->lpFileName,
        Gcreate->dwDesiredAccess,
        Gcreate->dwShareMode,
        Gcreate->lpSecurityAttributes,
        Gcreate->dwCreationDisposition,
        Gcreate->dwFlagsAndAttributes,
        Gcreate->hTemplateFile
    );
    return 0;
}
// 远程创建文件
BOOL RemoteCreateFile(DWORD dwProcessID, const char* szFilePathName)
{
    BOOL bRet;
    DWORD dwThread;
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwThreadFunSize;
    CREATEFILE_PARAM GCreateFile;
    LPVOID lpFilePathName;
    LPVOID lpRemoteThreadAddr;
    LPVOID lpFileParamAddr;
    DWORD dwFunAddr;
    HMODULE hModule;

    bRet = 0;
    hProcess = 0;
    dwThreadFunSize = 0x400;

    // 1. 获取进程句柄
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
    if (hProcess == NULL)
        return FALSE;

    // 2. 分配三段内存：存储参数、线程函数、文件名
    // 2.1 用来存储文件名
    lpFilePathName = VirtualAllocEx(hProcess, NULL, strlen(szFilePathName) + 1, MEM_COMMIT, PAGE_READWRITE);
    // 2.2 用来存储线程函数
    lpRemoteThreadAddr = VirtualAllocEx(hProcess, NULL, dwThreadFunSize, MEM_COMMIT, PAGE_READWRITE);
    // 2.3 用来存储参数
    lpFileParamAddr = VirtualAllocEx(hProcess, NULL, sizeof(CREATEFILE_PARAM), MEM_COMMIT, PAGE_READWRITE);

    // 3. 初始化CreateFile参数
    GCreateFile.dwDesiredAccess = GENERIC_READ | GENERIC_WRITE;
    GCreateFile.dwShareMode = 0;
    GCreateFile.lpSecurityAttributes = NULL;
    GCreateFile.dwCreationDisposition = OPEN_ALWAYS;
    GCreateFile.dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    GCreateFile.hTemplateFile = NULL;

    // 4. 获取CreateFile 地址
    hModule = LoadLibraryA("kernel32.dll");
    GCreateFile.dwCreateAPIAddr = (DWORD)GetProcAddress(hModule, "CreateFileA");
    FreeLibrary(hModule);
    // 5. 初始化CreateFile 文件名
    GCreateFile.lpFileName = (LPSTR)lpFilePathName;
    // 6. 修改线程函数起始地址
    dwFunAddr = (DWORD)CreateFileThreadProc;
    if (*((BYTE*)dwFunAddr) == 0xE9)
        dwFunAddr = dwFunAddr + 5 + *(DWORD*)(dwFunAddr + 1);

    // 7. 开始复制
    // 7.1 拷贝文件名
    WriteProcessMemory(hProcess, lpFilePathName, szFilePathName, strlen(szFilePathName) + 1, 0);
    // 7.2 拷贝线程函数
    WriteProcessMemory(hProcess, lpRemoteThreadAddr, (LPVOID)dwFunAddr, dwThreadFunSize, 0);
    // 7.3 拷贝参数
    WriteProcessMemory(hProcess, lpFileParamAddr, &GCreateFile, sizeof(CREATEFILE_PARAM), 0);

    // 8. 创建远程线程
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpRemoteThreadAddr, lpFileParamAddr, 0, &dwThread);

    // 9. 关闭进程句柄
    CloseHandle(hProcess);

    return TRUE;
}

int main()
{
    CreateFileA("D:\\A.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    //RemoteCreateFile(18624, "C:\\Users\\AAAAAAA\\source\\repos\\ConsoleApplication3\\Release\\a.txt");
    std::cout << "Hello World!\n";
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
