#ifndef DLL_KERNEL32_H
#define DLL_KERNEL32_H

#include "c_types.h"
#include "win_types.h"

typedef void*  FARPROC;
typedef HANDLE HMODULE;
typedef HANDLE HGLOBAL;
typedef HANDLE HLOCAL;

#define MAX_PATH 260

#define INVALID_HANDLE_VALUE ((HANDLE)(-1))

#define CURRENT_PROCESS ((HANDLE)(-1))
#define CURRENT_THREAD  ((HANDLE)(-2))

#define MEM_COMMIT   0x00001000
#define MEM_RESERVE  0x00002000
#define MEM_DECOMMIT 0x00004000
#define MEM_RELEASE  0x00008000

#define PAGE_NOACCESS          0x00000001
#define PAGE_READONLY          0x00000002
#define PAGE_READWRITE         0x00000004
#define PAGE_WRITECOPY         0x00000008
#define PAGE_EXECUTE           0x00000010
#define PAGE_EXECUTE_READ      0x00000020
#define PAGE_EXECUTE_READWRITE 0x00000040
#define PAGE_EXECUTE_WRITECOPY 0x00000080

#define INFINITE       0xFFFFFFFF
#define WAIT_ABANDONED 0x00000080
#define WAIT_OBJECT_0  0x00000000
#define WAIT_TIMEOUT   0x00000102
#define WAIT_FAILED    0xFFFFFFFF

#define STD_INPUT_HANDLE  ((DWORD)(-10))
#define STD_OUTPUT_HANDLE ((DWORD)(-11))
#define STD_ERROR_HANDLE  ((DWORD)(-12))

#define GENERIC_ALL     0x10000000
#define GENERIC_EXECUTE 0x20000000
#define GENERIC_WRITE   0x40000000
#define GENERIC_READ    0x80000000

#define FILE_SHARE_DELETE 0x00000004
#define FILE_SHARE_READ   0x00000001
#define FILE_SHARE_WRITE  0x00000002

#define CREATE_ALWAYS     2
#define CREATE_NEW        1
#define OPEN_ALWAYS       4
#define OPEN_EXISTING     3
#define TRUNCATE_EXISTING 5 

#define FILE_ATTRIBUTE_ARCHIVE   0x20
#define FILE_ATTRIBUTE_ENCRYPTED 0x4000
#define FILE_ATTRIBUTE_HIDDEN    0x2
#define FILE_ATTRIBUTE_NORMAL    0x80
#define FILE_ATTRIBUTE_OFFLINE   0x1000
#define FILE_ATTRIBUTE_READONLY  0x1
#define FILE_ATTRIBUTE_SYSTEM    0x4
#define FILE_ATTRIBUTE_TEMPORARY 0x100

#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000
#define FILE_FLAG_NO_BUFFERING    0x20000000
#define FILE_FLAG_WRITE_THROUGH   0x80000000

typedef DWORD (*ThreadProc_t)(LPVOID lpParameter);

typedef HMODULE (*LoadLibraryA_t)
(
    LPCSTR lpLibFileName
);

typedef HMODULE (*LoadLibraryW_t)
(
    LPCWSTR lpLibFileName
);

typedef HMODULE (*LoadLibraryExA_t)
(
    LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags
);

typedef HMODULE(*LoadLibraryExW_t)
(
    LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags
);

typedef BOOL (*FreeLibrary_t)
(
    HMODULE hLibModule
);

typedef FARPROC (*GetProcAddress_t)
(
    HMODULE hModule, LPCSTR lpProcName
);

typedef LPVOID (*VirtualAlloc_t)
(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect
);

typedef BOOL (*VirtualFree_t)
(
    LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType
);

typedef BOOL (*VirtualProtect_t)
(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect
);

typedef HANDLE (*CreateThread_t)
(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, ThreadProc_t lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
);

typedef void (*ExitThread_t)
(
    DWORD dwExitCode
);

typedef BOOL (*FlushInstructionCache_t)
(
    HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize
);

typedef HANDLE (*CreateMutexA_t)
(
    POINTER lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName
);

typedef BOOL (*ReleaseMutex_t)
(
    HANDLE hMutex
);

typedef void (*Sleep_t)
(
    DWORD dwMilliseconds
);

typedef DWORD (*WaitForSingleObject_t)
(
    HANDLE hHandle, DWORD dwMilliseconds
);

typedef BOOL (*CloseHandle_t)
(
    HANDLE hObject
);

typedef LPSTR (*GetCommandLineA_t)();

typedef LPWSTR (*GetCommandLineW_t)();

typedef HLOCAL (*LocalFree_t)
(
    HLOCAL hMem
);

typedef HANDLE (*GetStdHandle_t)
(
    DWORD nStdHandle
);

typedef void (*ExitProcess_t)
(
    UINT uExitCode
);

typedef HANDLE (*CreateFileA_t)
(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    POINTER lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile
);

typedef BOOL (*GetFileSizeEx_t)
(
    HANDLE hFile, LONGLONG* lpFileSize
);

typedef BOOL (*ReadFile_t)
(
    HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    DWORD* lpNumberOfBytesRead, POINTER lpOverlapped
);

typedef BOOL (*WriteFile_t)
(
    HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    DWORD* lpNumberOfBytesWritten, POINTER lpOverlapped
);

#endif // DLL_KERNEL32_H
