#include "c_types.h"
#include "win_types.h"
#include "dll_kernel32.h"
#include "hash_api.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "boot.h"

// a flag for calculate offset to Argument_Stub
#pragma warning(push)
#pragma warning(disable: 4276)
extern void Argument_Stub();
#pragma warning(pop)

// NOT using stdio is to ensure that no runtime instructions
// are introduced to avoid compiler optimization link errors
// that cause the extracted template to contain incorrect
// relative/absolute memory addresses.

static LoadLibraryA_t LoadLibraryA;
static CreateFileA_t  CreateFileA;
static WriteFile_t    WriteFile;
static CloseHandle_t  CloseHandle;

typedef int (*printf_s_t)(const char* format, ...);
static printf_s_t printf_s;

bool saveStandard();
bool savePipeline();
bool saveTemplate(LPSTR path, void* data, uint size);

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
    if (!saveStandard())
    {
        return 1;
    }
    if (!savePipeline())
    {
        return 2;
    }
    printf_s("build template successfully\n");
    return 0;
}

bool saveStandard()
{
#ifdef _WIN64
    LPSTR path = "../dist/standard/PELoader_x64.bin";
#elif _WIN32
    LPSTR path = "../dist/standard/PELoader_x86.bin";
#endif
    uintptr begin = (uintptr)(&Boot);
    uintptr end   = (uintptr)(&Argument_Stub);
    uintptr size  = end - begin;
    return saveTemplate(path, (byte*)begin, size);
}

bool savePipeline()
{
#ifdef _WIN64
    LPSTR path = "../dist/pipeline/PELoader_x64.bin";
#elif _WIN32
    LPSTR path = "../dist/pipeline/PELoader_x86.bin";
#endif
    uintptr begin = (uintptr)(&Boot);
    uintptr end   = (uintptr)(&InitRuntime);
    uintptr size  = end - begin;
    return saveTemplate(path, (byte*)begin, size);
}

bool saveTemplate(LPSTR path, void* data, uint size)
{
    HANDLE hFile = CreateFileA(
        path, GENERIC_WRITE, 0, NULL, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf_s("failed to create output file: 0x%X\n", GetLastErrno());
        return false;
    }
    if (!WriteFile(hFile, data, (DWORD)size, NULL, NULL))
    {
        printf_s("failed to write template: 0x%X\n", GetLastErrno());
        return false;
    }
    if (!CloseHandle(hFile))
    {
        printf_s("failed to close file: 0x%X\n", GetLastErrno());
        return false;
    }
    return true;
}
