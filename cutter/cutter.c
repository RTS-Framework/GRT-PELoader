#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "hash_api.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "epilogue.h"

// NOT using stdio is to ensure that no runtime instructions
// are introduced to avoid compiler optimization link errors
// that cause the extracted module to contain incorrect
// relative/absolute memory addresses.

static LoadLibraryA_t LoadLibraryA;
static CreateFileA_t  CreateFileA;
static WriteFile_t    WriteFile;
static CloseHandle_t  CloseHandle;

typedef int (*printf_s_t)(const char* format, ...);
static printf_s_t printf_s;

static void init()
{
    LoadLibraryA = FindAPI_A("kernel32.dll", "LoadLibraryA");
    CreateFileA  = FindAPI_A("kernel32.dll", "CreateFileA");
    WriteFile    = FindAPI_A("kernel32.dll", "WriteFile");
    CloseHandle  = FindAPI_A("kernel32.dll", "CloseHandle");

    HMODULE hModule = LoadLibraryA("msvcrt.dll");
    if (hModule == NULL)
    {
        return;
    }
    printf_s = FindAPI_A("msvcrt.dll", "printf_s");
}

#pragma comment(linker, "/ENTRY:EntryPoint")
int EntryPoint()
{
    init();

    uintptr begin = (uintptr)(&InitPELoader);
    uintptr end   = (uintptr)(&Epilogue);
    uintptr size  = end - begin;

    // extract module and save to file
#ifdef _WIN64
    LPSTR path = "../dist/module/PELoader_x64.bin";
#elif _WIN32
    LPSTR path = "../dist/module/PELoader_x86.bin";
#endif
    HANDLE hFile = CreateFileA(
        path, GENERIC_WRITE, 0, NULL, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf_s("failed to create output file: 0x%X\n", GetLastErrno());
        return 1;
    }
    if (!WriteFile(hFile, (byte*)begin, (DWORD)size, NULL, NULL))
    {
        printf_s("failed to write module: 0x%X\n", GetLastErrno());
        return 2;
    }
    if (!CloseHandle(hFile))
    {
        printf_s("failed to close file: 0x%X\n", GetLastErrno());
        return 3;
    }

    printf_s("cut module successfully\n");
    return 0;
}
