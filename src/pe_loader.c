#include "c_types.h"
#include "win_types.h"
#include "win_structs.h"
#include "dll_kernel32.h"
#include "dll_msvcrt.h"
#include "dll_ucrtbase.h"
#include "dll_shell32.h"
#include "lib_memory.h"
#include "lib_string.h"
#include "hash_api.h"
#include "rel_addr.h"
#include "pe_image.h"
#include "win_api.h"
#include "errno.h"
#include "runtime.h"
#include "pe_loader.h"
#include "debug.h"

#define MAIN_MEM_PAGE_SIZE 4096

typedef struct {
    // store config from argument
    Runtime_M*   Runtime;
    PELoader_Cfg Config;

    // store runtime option
    bool NotEraseInstruction;
    bool NotAdjustProtect;

    // process environment
    PEB* PEB; // process environment block
    PML* PML; // process module list (snapshot)

    // core dll address
    HMODULE hKernel32;

    // API addresses
    VirtualAlloc_t        VirtualAlloc;
    VirtualFree_t         VirtualFree;
    VirtualProtect_t      VirtualProtect;
    LoadLibraryA_t        LoadLibraryA;
    FreeLibrary_t         FreeLibrary;
    GetProcAddress_t      GetProcAddress;
    CreateThread_t        CreateThread;
    ExitThread_t          ExitThread;
    CreateMutexA_t        CreateMutexA;
    ReleaseMutex_t        ReleaseMutex;
    WaitForSingleObject_t WaitForSingleObject;
    CreateFileA_t         CreateFileA;
    CloseHandle_t         CloseHandle;
    GetCommandLineA_t     GetCommandLineA;
    GetCommandLineW_t     GetCommandLineW;
    LocalFree_t           LocalFree;
    GetStdHandle_t        GetStdHandle;

    // loader context
    void* MainMemPage;  // store all structures
    void* PEBackup;     // PE image backup
    uint  PEBackupSize; // PE image backup size
    bool  IsRunning;    // execution flag
    uint  ExitCode;     // exit code from exit

    // loader resource
    HANDLE hMutex;   // global mutex
    HANDLE hFileNUL; // for ignore console
    HANDLE StatusMu; // lock loader status
    HANDLE hThread;  // thread at EntryPoint

    // store PE image information
    uintptr PEImage;
    uintptr EntryPoint;
    uintptr ImageBase;
    uint32  ImageSize;
    uintptr Section;

    Image_FileHeader     FileHeader;
    Image_OptionalHeader OptHeader;
    Image_DataDirectory* DataDirectory;

    // store info need fixed when execute
    uintptr ExportTable;
    uint32  ExportTableSize;
    uintptr ImportTable;
    uint32  ImportTableSize;
    uintptr DelayImportTable;
    uint32  DelayImportTableSize;

    // about characteristics
    bool IsDLL;
    bool IsFixed;

    // store TLS data template
    void* TLSBlock;
    uint  TLSLen;

    // store TLS callback list
    TLSCallback_t* TLSList;

    // about command line arguments
    int     argc;
    LPSTR*  argv_a;
    LPWSTR* argv_w;

    // about msvcrt/ucrtbase on exit
    void** on_exit;
    int32  num_exit;
} PELoader;

// PE loader methods
void* LDR_GetProc(byte* name);
uint  LDR_ExitCode();
errno LDR_Start();
errno LDR_Wait();
errno LDR_Execute();
errno LDR_Exit(uint32 exitCode);
errno LDR_Destroy();

static PELoader* getPELoaderPointer();

static void* allocMainMemPage(Runtime_M* runtime, PELoader_Cfg* config);
static bool  initPELoaderAPI(PELoader* loader);
static bool  adjustPageProtect(PELoader* loader, DWORD* old);
static bool  recoverPageProtect(PELoader* loader, DWORD protect);
static errno initPELoaderEnv(PELoader* loader);
static errno loadPEImage(PELoader* loader);
static bool  parsePEImage(PELoader* loader);
static bool  checkPEImage(PELoader* loader);
static bool  mapSections(PELoader* loader);
static bool  fixRelocTable(PELoader* loader);
static bool  initTLSDirectory(PELoader* loader);
static void  prepareExportTable(PELoader* loader);
static void  prepareImportTable(PELoader* loader);
static void  prepareDelayImportTable(PELoader* loader);
static bool  backupPEImage(PELoader* loader);
static bool  lockMainMemPage(PELoader* loader);
static void  erasePELoaderMethods(PELoader* loader);
static errno cleanPELoader(PELoader* loader);
static void  setPELoaderPointer(PELoader* loader);
static void  cleanInitStack();

static bool ldr_lock();
static bool ldr_unlock();
static bool ldr_lock_status();
static bool ldr_unlock_status();

static void* ldr_GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
static void* ldr_get_hooks(LPCWSTR module, LPCSTR lpProcName);

static errno ldr_init_mutex();
static bool  ldr_copy_mapped_image();
static void* ldr_process_export(LPSTR name);
static bool  ldr_process_import();
static bool  ldr_process_delay_import();
static errno ldr_start_process();
static void  ldr_alloc_tls_block();
static void  ldr_free_tls_block();
static void  ldr_tls_callback(DWORD dwReason);
static void  ldr_register_exit(void* func);
static void  ldr_do_exit();
static void  ldr_exit_process(UINT uExitCode);
static void  ldr_pointer_stub();
static void  ldr_epilogue();

static void pe_entry_point();
static bool pe_dll_main(DWORD dwReason, bool setExitCode);
static void set_exit_code(uint code);
static void set_running(bool run);
static bool is_running();
static void clean_run_data();
static void reset_handler();
static uint restart_image();

// hooks about kernel32.dll
LPSTR   hook_GetCommandLineA();
LPWSTR  hook_GetCommandLineW();
LPWSTR* hook_CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs);
HANDLE  hook_GetStdHandle(DWORD nStdHandle);
HANDLE  hook_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
);
HANDLE  stub_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId, DWORD cc
);
void stub_ExecuteThread(LPVOID lpParameter);
void hook_ExitThread(DWORD dwExitCode);
void hook_ExitProcess(UINT uExitCode);

// hooks about msvcrt.dll
int __cdecl hook_msvcrt_getmainargs(
    int* argc, byte*** argv, byte*** env, int doWildCard, void* startInfo
);
int __cdecl hook_msvcrt_wgetmainargs(
    int* argc, uint16*** argv, uint16*** env, int doWildCard, void* startInfo
);
int   __cdecl hook_msvcrt_atexit(void* func);
void* __cdecl hook_msvcrt_onexit(void* func);
void* __cdecl hook_msvcrt_dllonexit(void* func, void* pbegin, void* pend);
void  __cdecl hook_msvcrt_exit(int exitcode);

uint __cdecl hook_msvcrt_beginthread(
    void* proc, uint32 stackSize, void* arg
);
uint __cdecl hook_msvcrt_beginthreadex(
    void* security, uint32 stackSize, void* proc, 
    void* arg, uint32 flag, uint32* tid
);
void __cdecl hook_msvcrt_endthread();
void __cdecl hook_msvcrt_endthreadex(uint32 code);

// hooks about ucrtbase.dll
int*      __cdecl hook_ucrtbase_p_argc();
byte***   __cdecl hook_ucrtbase_p_argv();
uint16*** __cdecl hook_ucrtbase_p_wargv();

int  __cdecl hook_ucrtbase_atexit(void* func);
int  __cdecl hook_ucrtbase_onexit(void* table, void* func);
void __cdecl hook_ucrtbase_exit(int exitcode);

uint __cdecl hook_ucrtbase_beginthread(
    void* proc, uint32 stackSize, void* arg
);
uint __cdecl hook_ucrtbase_beginthreadex(
    void* security, uint32 stackSize, void* proc, 
    void* arg, uint32 flag, uint32* tid
);
void __cdecl hook_ucrtbase_endthread();
void __cdecl hook_ucrtbase_endthreadex(uint32 code);

void loadCommandLineToArgv();

PELoader_M* InitPELoader(Runtime_M* runtime, PELoader_Cfg* config)
{
    if (!InitDebugger())
    {
        SetLastErrno(ERR_LOADER_INIT_DEBUGGER);
        return NULL;
    }
    // alloc memory for store loader structure
    void* memPage = allocMainMemPage(runtime, config);
    if (memPage == NULL)
    {
        SetLastErrno(ERR_LOADER_ALLOC_MAIN_MEM_PAGE);
        return NULL;
    }
    // set structure address
    uintptr address = (uintptr)memPage;
    uintptr loaderAddr = address + 1000 + runtime->Random.UintN(0, 128);
    uintptr moduleAddr = address + 3000 + runtime->Random.UintN(0, 128);
    // allocate loader memory
    PELoader* loader = (PELoader*)loaderAddr;
    mem_init(loader, sizeof(PELoader));
    // copy loader configuration
    mem_copy(&loader->Config, config, sizeof(PELoader_Cfg));
    // store runtime option
    Runtime_Opts opts = {
        .NotEraseInstruction = false,
        .NotAdjustProtect    = false,
    };
    runtime->Core.Options(&opts);
    loader->NotEraseInstruction = opts.NotEraseInstruction;
    loader->NotAdjustProtect    = opts.NotAdjustProtect;
    // store process environment
    loader->PEB = runtime->Env.GetPEB();
    loader->PML = runtime->Env.GetPML();
    // store core dll handle
    loader->hKernel32 = runtime->DLL.GetKernel32();
    // store config and context
    loader->Runtime = runtime;
    loader->MainMemPage = memPage;
    // initialize loader
    DWORD oldProtect = 0;
    errno errno = NO_ERROR;
    for (;;)
    {
        if (!initPELoaderAPI(loader))
        {
            errno = ERR_LOADER_INIT_API;
            break;
        }
        if (!adjustPageProtect(loader, &oldProtect))
        {
            errno = ERR_LOADER_ADJUST_PROTECT;
            break;
        }
        errno = initPELoaderEnv(loader);
        if (errno != NO_ERROR)
        {
            break;
        }
        errno = loadPEImage(loader);
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!backupPEImage(loader))
        {
            errno = ERR_LOADER_BACKUP_PE_IMAGE;
            break;
        }
        if (!lockMainMemPage(loader))
        {
            errno = ERR_LOADER_LOCK_MAIN_MEM_PAGE;
            break;
        }
        break;
    }
    if (errno == NO_ERROR || errno > ERR_LOADER_ADJUST_PROTECT)
    {
        erasePELoaderMethods(loader);
    }
    setPELoaderPointer(loader);
    if (oldProtect != 0)
    {
        if (!recoverPageProtect(loader, oldProtect) && errno == NO_ERROR)
        {
            errno = ERR_LOADER_RECOVER_PROTECT;
        }
    }
    if (errno != NO_ERROR)
    {
        cleanPELoader(loader);
        cleanInitStack();
        SetLastErrno(errno);
        return NULL;
    }
    // set watchdog reset handler
    runtime->Watchdog.SetHandler(GetFuncAddr(&reset_handler));
    // create methods for loader
    PELoader_M* module = (PELoader_M*)moduleAddr;
    // process variables
    module->ImageBase  = (void*)(loader->PEImage);
    module->EntryPoint = (void*)(loader->EntryPoint);
    module->IsDLL      = loader->IsDLL;
    module->ExitCode   = 0;
    module->RuntimeMu  = runtime->Data.Mutex;
    // loader module methods
    module->GetProc  = GetFuncAddr(&LDR_GetProc);
    module->ExitCode = GetFuncAddr(&LDR_ExitCode);
    module->Start    = GetFuncAddr(&LDR_Start);
    module->Wait     = GetFuncAddr(&LDR_Wait);
    module->Execute  = GetFuncAddr(&LDR_Execute);
    module->Exit     = GetFuncAddr(&LDR_Exit);
    module->Destroy  = GetFuncAddr(&LDR_Destroy);
    cleanInitStack();
    return module;
}

static void* allocMainMemPage(Runtime_M* runtime, PELoader_Cfg* config)
{
#ifdef _WIN64
    uint pHash = 0xAA8D188A1F0862DC;
    uint hKey  = 0x6EDC8B580ACA6913;
#elif _WIN32
    uint pHash = 0xA7CFDD6F;
    uint hKey  = 0x0F2BB61F;
#endif
    HMODULE hKernel32 = runtime->DLL.GetKernel32();
    VirtualAlloc_t virtualAlloc = config->FindAPI(hKernel32, pHash, hKey);
    if (virtualAlloc == NULL)
    {
        return NULL;
    }
    SIZE_T size = MAIN_MEM_PAGE_SIZE;
    size += (1 + runtime->Random.UintN(0, 16)) * 4096;
    LPVOID addr = virtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (addr == NULL)
    {
        return NULL;
    }
    runtime->Random.Buffer(addr, (int64)size);
    dbg_log("[PE Loader]", "Main Memory Page: 0x%zX", addr);
    return addr;
}

static bool initPELoaderAPI(PELoader* loader)
{
    typedef struct { 
        uint pHash; uint hKey; void* proc;
    } winapi;
    winapi list[] =
#ifdef _WIN64
    {
        { 0xA0A93FC801DCA874, 0xDC0D07D21838938D }, // VirtualAlloc
        { 0x502A741BB71E85B4, 0x723D605A7B2777B4 }, // VirtualFree
        { 0x9DE9DCDBC168BCB5, 0xAEAB0A9DE37E8DA5 }, // VirtualProtect
        { 0x765460317300B27F, 0x45EC64F6B9C67579 }, // LoadLibraryA
        { 0x4F1C84C32514C065, 0x4163AE252BE32A0A }, // FreeLibrary
        { 0x28E536A81B0E5FBC, 0x112B9FA92C790A9F }, // GetProcAddress
        { 0x915A9A67F9624C94, 0x0286C91B1146AA8A }, // CreateThread
        { 0x4437AAD530C05680, 0x255CF8D04E88F38F }, // ExitThread
        { 0x1A72BB5222C92A04, 0x290DD2AD7712F521 }, // CreateMutexA
        { 0x60538A615A3DC39D, 0x26A74F6C0A6DA07C }, // ReleaseMutex
        { 0x62BCB99CC882FABE, 0x14529C2202547DB1 }, // WaitForSingleObject
        { 0xC9FC614CEC6418EA, 0xEB95F0FFDD9A0164 }, // CreateFileA
        { 0x59F5D1E90A85FD71, 0x76C1F7E62CED2080 }, // CloseHandle
        { 0x60ED37D97353DEB7, 0xDC1DBF0237B732AE }, // GetCommandLineA
        { 0x57D3F898478FF91F, 0xA7ADC351AF5C208F }, // GetCommandLineW
        { 0xC292CD4CFBA787F8, 0x2E76D6A9ADA85FD2 }, // LocalFree
        { 0x9A283FBDAD1BBE92, 0x1F174C21E88F2DD4 }, // GetStdHandle
    };
#elif _WIN32
    {
        { 0x689AA1E3, 0x3A5308D4 }, // VirtualAlloc
        { 0x640BD6A8, 0x64EA9AC2 }, // VirtualFree
        { 0x3077A74E, 0x7155ED28 }, // VirtualProtect
        { 0xB04095D2, 0x6468B59D }, // LoadLibraryA
        { 0xF25AB58A, 0xD32B963C }, // FreeLibrary
        { 0x76C5A295, 0xC8390D32 }, // GetProcAddress
        { 0xDDAFACA6, 0x6E386ED3 }, // CreateThread
        { 0xC8B01CF6, 0xE6D32B90 }, // ExitThread
        { 0x96AB272A, 0x5D0E1AAA }, // CreateMutexA
        { 0xA260CC33, 0xC242D9C7 }, // ReleaseMutex
        { 0x209FAE3F, 0x98BFE3BF }, // WaitForSingleObject
        { 0x4E5E3A68, 0x16B42ABE }, // CreateFileA
        { 0xC92AF0C7, 0xED67E11B }, // CloseHandle
        { 0x21E3793F, 0x15F9DE4B }, // GetCommandLineA
        { 0xC5B2807C, 0x223C7896 }, // GetCommandLineW
        { 0x8935E1E7, 0x891771CD }, // LocalFree
        { 0xD7AB6E7F, 0x9EAFCC67 }, // GetStdHandle
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        winapi item = list[i];
        void*  proc = loader->Config.FindAPI(loader->hKernel32, item.pHash, item.hKey);
        if (proc == NULL)
        {
            return false;
        }
        list[i].proc = proc;
    }

    loader->VirtualAlloc        = list[0x00].proc;
    loader->VirtualFree         = list[0x01].proc;
    loader->VirtualProtect      = list[0x02].proc;
    loader->LoadLibraryA        = list[0x03].proc;
    loader->FreeLibrary         = list[0x04].proc;
    loader->GetProcAddress      = list[0x05].proc;
    loader->CreateThread        = list[0x06].proc;
    loader->ExitThread          = list[0x07].proc;
    loader->CreateMutexA        = list[0x08].proc;
    loader->ReleaseMutex        = list[0x09].proc;
    loader->WaitForSingleObject = list[0x0A].proc;
    loader->CreateFileA         = list[0x0B].proc;
    loader->CloseHandle         = list[0x0C].proc;
    loader->GetCommandLineA     = list[0x0D].proc;
    loader->GetCommandLineW     = list[0x0E].proc;
    loader->LocalFree           = list[0x0F].proc;
    loader->GetStdHandle        = list[0x10].proc;

    // erase data in the large stack
    mem_init(list, sizeof(list));
    return true;
}

static errno initPELoaderEnv(PELoader* loader)
{
    // create global mutex
    HANDLE hMutex = loader->CreateMutexA(NULL, false, NAME_LDR_MUTEX_GLOBAL);
    if (hMutex == NULL)
    {
        return ERR_LOADER_CREATE_MUTEX_GLOBAL;
    }
    loader->hMutex = hMutex;
    // lock mutex
#ifndef NO_RUNTIME
    if (!loader->Runtime->Resource.LockMutex(hMutex))
    {
        loader->CloseHandle(hMutex);
        loader->hMutex = NULL;
        return ERR_LOADER_LOCK_MUTEX_GLOBAL;
    }
#endif // NO_RUNTIME

    // create NUL file if ignore standard handle
    if (loader->Config.IgnoreStdIO)
    {
        byte nul[] = { 'N', 'U', 'L', '\x00' };
        HANDLE hFileNUL = loader->CreateFileA(
            nul, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
        );   
        if (hFileNUL == INVALID_HANDLE_VALUE)
        {
            return ERR_LOADER_CREATE_FILE_NUL;
        } 
        loader->hFileNUL = hFileNUL;
        // overwrite handle in config
        loader->Config.StdInput  = hFileNUL;
        loader->Config.StdOutput = hFileNUL;
        loader->Config.StdError  = hFileNUL;
        // lock file
    #ifndef NO_RUNTIME
        if (!loader->Runtime->Resource.LockFile(hFileNUL))
        {
            loader->CloseHandle(hFileNUL);
            loader->hFileNUL = NULL;
            return ERR_LOADER_LOCK_FILE_NUL;
        }
    #endif // NO_RUNTIME
    }
    return NO_ERROR;
}

static errno loadPEImage(PELoader* loader)
{
    if (!parsePEImage(loader))
    {
        return ERR_LOADER_PARSE_PE_IMAGE;
    }
    if (!checkPEImage(loader))
    {
        return ERR_LOADER_CHECK_PE_IMAGE;
    }
    if (!mapSections(loader))
    {
        return ERR_LOADER_MAP_SECTIONS;
    }
    if (!fixRelocTable(loader))
    {
        return ERR_LOADER_FIX_RELOC_TABLE;
    }
    if (!initTLSDirectory(loader))
    {
        return ERR_LOADER_INIT_TLS_DIRECTORY;
    }
    prepareExportTable(loader);
    prepareImportTable(loader);
    prepareDelayImportTable(loader);
    dbg_log("[PE Loader]", "PE Image: 0x%zX", loader->PEImage);
    return NO_ERROR;
}

static bool parsePEImage(PELoader* loader)
{
    uintptr imageAddr = (uintptr)(loader->Config.Image);
    if (imageAddr == 0)
    {
        return false;
    }
    // check image file header
    if ((*(byte*)(imageAddr+0)^0x7C) != ('M'^0x7C))
    {
        return false;
    }
    if ((*(byte*)(imageAddr+1)^0xA3) != ('Z'^0xA3))
    {
        return false;
    }
    // skip DOS stub
    uint32 hdrOffset = *(uint32*)(imageAddr + DOS_HEADER_SIZE - 4);
    // parse PE headers
    Image_NTHeaders*      ntHeaders  = (Image_NTHeaders*)(imageAddr + hdrOffset);
    Image_FileHeader*     fileHeader = &ntHeaders->FileHeader;
    Image_OptionalHeader* optHeader  = &ntHeaders->OptionalHeader;
    // check is a executable image
    WORD characteristics = fileHeader->Characteristics;
    if (!(characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
    {
        return false;
    }
    // erase timestamp in file header
    fileHeader->TimeDateStamp = 0;
    // calculate the address of the first Section
    uintptr fileAddr = imageAddr + hdrOffset + sizeof(ntHeaders->Signature);
    uintptr optAddr  = fileAddr + sizeof(Image_FileHeader);
    uint32  optSize  = fileHeader->SizeOfOptionalHeader;
    uintptr section  = optAddr + optSize;
    // store parse result
    loader->EntryPoint = optHeader->AddressOfEntryPoint;
    loader->ImageBase  = optHeader->ImageBase;
    loader->ImageSize  = optHeader->SizeOfImage;
    loader->Section    = section;
    loader->IsDLL      = characteristics & IMAGE_FILE_DLL;
    loader->IsFixed    = characteristics & IMAGE_FILE_RELOCS_STRIPPED;
    // store data directory
    loader->DataDirectory = optHeader->DataDirectory;
    // use mem_copy for reduce instruction size
    mem_copy(&loader->FileHeader, fileHeader, sizeof(Image_FileHeader));
    mem_copy(&loader->OptHeader, optHeader, sizeof(Image_OptionalHeader));
    return true;
}

static bool checkPEImage(PELoader* loader)
{
    // check PE image architecture
#ifdef _WIN64
    uint16 arch = IMAGE_FILE_MACHINE_AMD64;
#elif _WIN32
    uint16 arch = IMAGE_FILE_MACHINE_I386;
#endif
    Image_FileHeader* FileHeader = &loader->FileHeader;
    if (FileHeader->Machine != arch)
    {
        return false;
    }
    dbg_log("[PE Loader]", "Characteristics: 0x%X", FileHeader->Characteristics);
    return true;
}

static bool mapSections(PELoader* loader)
{
    Runtime_M* runtime = loader->Runtime;

    // select the memory page address
    LPVOID base = NULL;
    if (loader->IsFixed)
    {
        base = (LPVOID)(loader->OptHeader.ImageBase);
    }
    // append random memory size to image tail
    uint32 size = loader->ImageSize;
    size += (uint32)((1 + runtime->Random.UintN(0, 128)) * 4096);
    // allocate memory for map PE image
    DWORD type = MEM_COMMIT|MEM_RESERVE;
    void* mem = loader->VirtualAlloc(base, size, type, PAGE_EXECUTE_READWRITE);
    if (mem == NULL)
    {
        return false;
    }
    loader->PEImage = (uintptr)mem;
    // lock memory region with special argument for reuse PE image
#ifndef NO_RUNTIME
    if (!runtime->Memory.Lock(mem))
    {
        return false;
    }
#endif // NO_RUNTIME
    // map PE image sections to the memory
    uintptr peImage   = (uintptr)mem;
    uintptr imageAddr = (uintptr)(loader->Config.Image);
    Image_SectionHeader* section = (Image_SectionHeader*)(loader->Section);
    for (uint16 i = 0; i < loader->FileHeader.NumberOfSections; i++)
    {
        uint32 virtualAddress   = section->VirtualAddress;
        uint32 virtualSize      = section->VirtualSize;
        uint32 pointerToRawData = section->PointerToRawData;
        uint32 sizeOfRawData    = section->SizeOfRawData;
        byte* dst = (byte*)(peImage + virtualAddress);
        byte* src = (byte*)(imageAddr + pointerToRawData);
        uint32 len = sizeOfRawData;
        if (len > virtualSize)
        {
            len = virtualSize;
        }
        mem_copy(dst, src, len);
        section++;
    }
    // update EntryPoint absolute address
    loader->EntryPoint += peImage;
    // fill area before the first section
    section = (Image_SectionHeader*)(loader->Section);
    runtime->Crypto.EraseInstruction(mem, section->VirtualAddress);
    return true;
}

static bool fixRelocTable(PELoader* loader)
{
    if (loader->IsFixed)
    {
        return true;
    }
    Image_DataDirectory dd = loader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    uintptr peImage    = loader->PEImage;
    uintptr relocTable = peImage + dd.VirtualAddress;
    uint32  tableSize  = dd.Size;
    // check need relocation
    if (tableSize == 0)
    {
        return true;
    }
    void*  tableAddr  = (void*)relocTable; // for erase table after
    uint64 addrOffset = (int64)(loader->PEImage) - (int64)(loader->ImageBase);
    for (;;)
    {
        Image_BaseRelocation* baseReloc = (Image_BaseRelocation*)(relocTable);
        if (baseReloc->VirtualAddress == 0)
        {
            break;
        }
        uintptr relocPtr = relocTable + 8;
        uintptr dstAddr  = peImage + baseReloc->VirtualAddress;
        for (uint32 i = 0; i < (baseReloc->SizeOfBlock - 8) / 2; i++)
        {
            Image_Reloc reloc = *(Image_Reloc*)(relocPtr);
            uint32* patchAddr32;
            uint64* patchAddr64;
            switch (reloc.Type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            case IMAGE_REL_BASED_HIGHLOW:
                patchAddr32 = (uint32*)(dstAddr + reloc.Offset);
                *patchAddr32 += (uint32)(addrOffset);
                break;
            case IMAGE_REL_BASED_DIR64:
                patchAddr64 = (uint64*)(dstAddr + reloc.Offset);
                *patchAddr64 += (uint64)(addrOffset);
                break;
            default:
                return false;
            }
            relocPtr += sizeof(Image_Reloc);
        }
        relocTable += baseReloc->SizeOfBlock;
    }
    // destroy table for prevent extract raw PE image
    loader->Runtime->Random.Buffer(tableAddr, tableSize);
    return true;
}

static bool initTLSDirectory(PELoader* loader)
{
    Runtime_M* runtime = loader->Runtime;

    Image_DataDirectory dd = loader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    uintptr peImage   = loader->PEImage;
    uintptr tlsTable  = peImage + dd.VirtualAddress;
    uint32  tableSize = dd.Size;
    // check need initialize tls callback
    if (tableSize == 0)
    {
        return true;
    }
    Image_TLSDirectory* tls = (Image_TLSDirectory*)(tlsTable);
    // allocate memory for copy tls template data, the first 16 bytes
    // for store original TLS address and make sure 16 bytes-aligned
    uint size  = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
    uint total = 16 + size + tls->SizeOfZeroFill;
    // allocate memory for save tls template data
    uint  pSize = total + (uint)((1 + runtime->Random.UintN(0, 8)) * 4096);
    DWORD type  = MEM_COMMIT|MEM_RESERVE;
    void* block = loader->VirtualAlloc(NULL, pSize, type, PAGE_READWRITE);
    if (block == NULL)
    {
        return false;
    }
    runtime->Random.Buffer(block, (int64)size);
    loader->TLSBlock = block;
    loader->TLSLen   = total;
#ifndef NO_RUNTIME
    // lock memory region with special argument for reuse PE image
    if (!loader->Runtime->Memory.Lock(block))
    {
        return false;
    }
#endif // NO_RUNTIME
    uintptr start = (uintptr)block + 16;
    mem_copy((void*)(start), (void*)(tls->StartAddressOfRawData), size);
    mem_init((void*)(start + size), tls->SizeOfZeroFill);
    dbg_log("[PE Loader]", "TLS block template: 0x%zX", block);
    // record tls callback list
    loader->TLSList = (TLSCallback_t*)(tls->AddressOfCallBacks);
    // destroy tls template data and tls table for prevent extract raw PE image
    runtime->Random.Buffer((byte*)(tls->StartAddressOfRawData), size);
    runtime->Random.Buffer((byte*)tlsTable, tableSize);
    return true;
}

static void prepareExportTable(PELoader* loader)
{
    Image_DataDirectory dd = loader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    uintptr peImage = loader->PEImage;

    loader->ExportTable     = peImage + dd.VirtualAddress;
    loader->ExportTableSize = dd.Size;

    // erase timestamp in PE image
    if (dd.Size == 0)
    {
        return;
    }
    Image_ExportDirectory* export = (Image_ExportDirectory*)(loader->ExportTable);
    export->TimeDateStamp = 0;
}

static void prepareImportTable(PELoader* loader)
{
    Image_DataDirectory dd = loader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    uintptr peImage = loader->PEImage;

    loader->ImportTable     = peImage + dd.VirtualAddress;
    loader->ImportTableSize = dd.Size;

    // erase timestamp in PE image
    if (loader->ImportTableSize == 0)
    {
        return;
    }
    Image_ImportDescriptor* import = (Image_ImportDescriptor*)(loader->ImportTable);
    for (;;)
    {
        if (import->Name == 0)
        {
            break;
        }
        import->TimeDateStamp = 0;
        import++;
    }
}

static void prepareDelayImportTable(PELoader* loader)
{
    Image_DataDirectory dd = loader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    uintptr peImage = loader->PEImage;

    loader->DelayImportTable     = peImage + dd.VirtualAddress;
    loader->DelayImportTableSize = dd.Size;

    // erase timestamp in PE image
    if (loader->DelayImportTableSize == 0)
    {
        return;
    }
    Image_DelayloadDescriptor* dld = (Image_DelayloadDescriptor*)(loader->DelayImportTable);
    for (;;)
    {
        if (dld->DllNameRVA == 0)
        {
            break;
        }
        dld->TimeDateStamp = 0;
        dld++;
    }
}

// backupPEImage is used to execute PE image multi times.
static bool backupPEImage(PELoader* loader)
{
    Runtime_M* runtime = loader->Runtime;

    uint window = MAXIMUM_WINDOW_SIZE;
    uint chain  = MINIMUM_CHAIN_LEN;

    // calculate the compressed image size
    void*  image = (void*)(loader->PEImage);
    uint32 size  = loader->ImageSize;
    uint bakSize = runtime->Compressor.Compress(NULL, image, size, window, chain);
    if (bakSize == (uint)(-1))
    {
        return false;
    }
    loader->PEBackupSize = bakSize;

    // append random memory size to tail
    SIZE_T memSize = bakSize + (1 + runtime->Random.UintN(0, 128)) * 4096;
    // allocate memory for backup PE image
    DWORD type = MEM_COMMIT|MEM_RESERVE;
    void* mem = loader->VirtualAlloc(NULL, memSize, type, PAGE_READWRITE);
    if (mem == NULL)
    {
        return false;
    }
    loader->PEBackup = mem;

    // save compressed PE image(mapped)
    if (runtime->Compressor.Compress(mem, image, size, window, chain) == (uint)(-1))
    {
        return false;
    }

#ifndef NO_RUNTIME
    // lock memory region with special argument for reuse PE image
    if (!loader->Runtime->Memory.Lock(mem))
    {
        return false;
    }
#endif // NO_RUNTIME
    return true;
}

static bool lockMainMemPage(PELoader* loader)
{
#ifndef NO_RUNTIME
    if (!loader->Runtime->Memory.Lock(loader->MainMemPage))
    {
        return false;
    }
#endif // NO_RUNTIME
    return true;
}

__declspec(noinline)
static void erasePELoaderMethods(PELoader* loader)
{
    if (loader->NotEraseInstruction)
    {
        return;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&allocMainMemPage));
    uintptr end   = (uintptr)(GetFuncAddr(&erasePELoaderMethods));
    uintptr size  = end - begin;
    loader->Runtime->Crypto.EraseInstruction((void*)begin, size);
}

// ======================== these instructions will not be erased ========================

static errno cleanPELoader(PELoader* loader)
{
    Runtime_M* runtime = loader->Runtime;

    errno errno = NO_ERROR;

    CloseHandle_t closeHandle = loader->CloseHandle;
    VirtualFree_t virtualFree = loader->VirtualFree;

    if (closeHandle != NULL)
    {
        // close global mutex
        if (loader->hMutex != NULL)
        {
            if (!closeHandle(loader->hMutex) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_CLEAN_MUTEX_GLOBAL;
            }
        }
        // close NUL file
        if (loader->hFileNUL != NULL)
        {
            if (!closeHandle(loader->hFileNUL) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_CLEAN_FILE_NUL;
            }
        }
        // close status mutex
        if (loader->StatusMu != NULL)
        {
            if (!closeHandle(loader->StatusMu) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_CLEAN_MUTEX_STATUS;
            }
        }
    }

    if (virtualFree != NULL)
    {
        void* peImage  = (void*)(loader->PEImage);
        void* peBackup = loader->PEBackup;
        void* tlsBlock = loader->TLSBlock;
        void* memPage  = loader->MainMemPage;

        // release memory page for PE image
        if (peImage != NULL)
        {
            runtime->Crypto.EraseBuffer(peImage, loader->ImageSize);
            if (!virtualFree(peImage, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_PE_IMAGE;
            }
        }
        // release memory page for PE image backup
        if (peBackup != NULL)
        {
            runtime->Crypto.EraseBuffer(peBackup, loader->PEBackupSize);
            if (!virtualFree(peBackup, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_PE_IMAGE_BACKUP;
            }
        }
        // release memory page for TLS block template
        if (tlsBlock != NULL)
        {
            runtime->Crypto.EraseBuffer(tlsBlock, loader->TLSLen);
            if (!virtualFree(tlsBlock, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_TLS_BLOCK;
            }
        }
        // release main memory page
        if (memPage != NULL)
        {
            runtime->Crypto.EraseBuffer(memPage, MAIN_MEM_PAGE_SIZE);
            if (!virtualFree(memPage, 0, MEM_RELEASE) && errno == NO_ERROR)
            {
                errno = ERR_LOADER_FREE_MAIN_MEM;
            }
        }
    }
    return errno;
}

__declspec(noinline)
static bool adjustPageProtect(PELoader* loader, DWORD* old)
{
    if (loader->NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&InitPELoader));
    uintptr end   = (uintptr)(GetFuncAddr(&ldr_epilogue));
    uint    size  = end - begin;
    return loader->VirtualProtect((void*)begin, size, PAGE_EXECUTE_READWRITE, old);
}

__declspec(noinline)
static bool recoverPageProtect(PELoader* loader, DWORD protect)
{
    if (loader->NotAdjustProtect)
    {
        return true;
    }
    uintptr begin = (uintptr)(GetFuncAddr(&InitPELoader));
    uintptr end   = (uintptr)(GetFuncAddr(&ldr_epilogue));
    uint    size  = end - begin;
    DWORD   old;
    return loader->VirtualProtect((void*)begin, size, protect, &old);
}

#pragma optimize("", off)
__declspec(noinline)
static void cleanInitStack()
{
    byte data[2048];
    mem_init(data, sizeof(data));
}
#pragma optimize("", on)

static void setPELoaderPointer(PELoader* loader)
{
    uintptr stub = (uintptr)GetFuncAddr(&ldr_pointer_stub);
    *(PELoader**)(stub + 4) = loader;
}

static PELoader* getPELoaderPointer()
{
    uintptr stub = (uintptr)GetFuncAddr(&ldr_pointer_stub);
    return *(PELoader**)(stub + 4);
}

__declspec(noinline)
static bool ldr_lock()
{
    PELoader* loader = getPELoaderPointer();

    DWORD event = loader->WaitForSingleObject(loader->hMutex, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool ldr_unlock()
{
    PELoader* loader = getPELoaderPointer();

    return loader->ReleaseMutex(loader->hMutex);
}

__declspec(noinline)
static bool ldr_lock_status()
{
    PELoader* loader = getPELoaderPointer();

    if (loader->StatusMu == NULL)
    {
        return true;
    }
    DWORD event = loader->WaitForSingleObject(loader->StatusMu, INFINITE);
    return event == WAIT_OBJECT_0 || event == WAIT_ABANDONED;
}

__declspec(noinline)
static bool ldr_unlock_status()
{
    PELoader* loader = getPELoaderPointer();

    if (loader->StatusMu == NULL)
    {
        return true;
    }
    return loader->ReleaseMutex(loader->StatusMu);
}

__declspec(noinline)
void* ldr_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    // try to get procedure address
    if (hModule == HMODULE_GLEAM_RT)
    {
        dbg_log("[PE Loader]", "Get Runtime Method: %s", lpProcName);
        return loader->GetProcAddress(hModule, lpProcName);
    }
    if (lpProcName <= (LPCSTR)(0xFFFF))
    {
        dbg_log("[PE Loader]", "GetProcAddressByOrdinal: %d", lpProcName);
    } else {
        dbg_log("[PE Loader]", "GetProcAddress: %s", lpProcName);
    }
    void* proc = loader->GetProcAddress(hModule, lpProcName);
    if (proc == NULL)
    {
        return NULL;
    }
    // get process module list snapshot
    PML* pml = runtime->Env.GetPML();
    // use "mem_init" for prevent incorrect compiler
    // optimize and generate incorrect template
    uint16 modName[MAX_PATH];
    mem_init(modName, sizeof(modName));
    // get dll base name for calculate module hash
    if (GetModuleBaseName(pml, hModule, modName, MAX_PATH) == 0)
    {
        SetLastErrno(ERR_LOADER_MODULE_NOT_FOUND);
        return NULL;
    }
    // if lpProcName is a ordinal, get procedure name
    if (lpProcName <= (LPCSTR)(0xFFFF))
    {
        lpProcName = GetProcedureName(pml, hModule, proc);
        if (lpProcName == NULL)
        {
            // erase data in the large stack
            mem_init(modName, sizeof(modName));
            return proc;
        }
    }
    // check is PE Loader internal method or need hook
    void* hook = ldr_get_hooks(modName, lpProcName);
    // erase data in the large stack
    mem_init(modName, sizeof(modName));
    if (hook != NULL)
    {
        return hook;
    }
    return proc;
}

__declspec(noinline)
static void* ldr_get_hooks(LPCWSTR module, LPCSTR lpProcName)
{
    typedef struct {
        uint mHash; uint pHash; uint hKey; void* hook;
    } hook;
    hook list[] =
#ifdef _WIN64
    {
        { 0x1157A12A3CCCBCF0, 0x110E5A6CEF844687, 0xE3761DE4EFE39ED4, GetFuncAddr(&ldr_GetProcAddress)          },
        { 0xA578CF08ED69EB2D, 0x5C6FEC81CAA3B1A3, 0xACD191FECA51AACF, GetFuncAddr(&hook_GetCommandLineA)        },
        { 0x6D146EC2E0B343D2, 0xE9F55CD29DAE8AEA, 0xEF67344AA182DC0C, GetFuncAddr(&hook_GetCommandLineW)        },
        { 0x1C0FD2DE1BAA2730, 0x8FF152F2B3ED26CC, 0x9FAB7B2D222B6907, GetFuncAddr(&hook_CommandLineToArgvW)     },
        { 0xABA2D3C157D8B296, 0x09CA0B0331C8BD1C, 0xCC386ABC0E08045D, GetFuncAddr(&hook_GetStdHandle)           },
        { 0xFA19C2C7C1BBC621, 0xC1D971E22F5FC759, 0x3FDC4AA7DA8799EE, GetFuncAddr(&hook_CreateThread)           },
        { 0x65920F946E5D24A0, 0xE23FD2A2E80059BB, 0xD9267EBA7C324D62, GetFuncAddr(&hook_ExitThread)             },
        { 0xCF2D53517606992B, 0xA1DC608BC8A2C347, 0x9356BD9C7805B6E8, GetFuncAddr(&hook_ExitProcess)            },
        { 0x62775469FFFD9C7A, 0xFCA810D1E000D143, 0x0A1AF99724E90A25, GetFuncAddr(&hook_ExitThread)             }, // RtlExitUserThread
        { 0xEBCDC8C2A543809C, 0x391AAC50931B2868, 0xA2FFC51FBA943F63, GetFuncAddr(&hook_ExitProcess)            }, // RtlExitUserProcess
        { 0x58984160F1FE2D28, 0xA4D203A7D8BBDFD1, 0x3C12788C06C58CA1, GetFuncAddr(&hook_msvcrt_getmainargs)     },
        { 0x299503685C2343A8, 0x116BD4CD1F7E3CA3, 0xBE556FDEE368FA15, GetFuncAddr(&hook_msvcrt_wgetmainargs)    },
        { 0x41C9EBD486586B4C, 0x37720312C6724AAF, 0x10BE59C3858FB45B, GetFuncAddr(&hook_msvcrt_atexit)          },
        { 0x3EE25FD510FAA7E6, 0xEDCAC470F5634857, 0x89E3761D64BAF329, GetFuncAddr(&hook_msvcrt_onexit)          },
        { 0x502F0B62EEE34674, 0xBBAA24D1B0FAB2F3, 0xF075658338A3ECD0, GetFuncAddr(&hook_msvcrt_dllonexit)       },
        { 0x232B0CFB48B3CB1F, 0xD6266A2CBD4E0E3A, 0x74897DEF2D79072F, GetFuncAddr(&hook_msvcrt_exit)            },
        { 0xFACCA36559994C46, 0xEFA7E38C80104906, 0x781A8FA9928DBB80, GetFuncAddr(&hook_msvcrt_exit)            }, // _exit
        { 0xF6BF6E0597E37FA9, 0x227E79498776B14A, 0xCB5DE4C1656298B8, GetFuncAddr(&hook_msvcrt_exit)            }, // _Exit
        { 0x2E5A2386256F1988, 0xBED38E18159EDA87, 0x36A63CE974070DF6, GetFuncAddr(&hook_msvcrt_exit)            }, // _cexit
        { 0xF34C0734CE7E1FDF, 0x1B850E91F78F61C4, 0x501B2D5B8A90982D, GetFuncAddr(&hook_msvcrt_exit)            }, // _c_exit
        { 0xF08832FA50E24941, 0xA0F1A74C037C9BDB, 0xF51522519723F887, GetFuncAddr(&hook_msvcrt_exit)            }, // quick_exit
        { 0x7D224772228250BD, 0x3F8A9889DC81C70D, 0xD37244D73E38F01D, GetFuncAddr(&hook_msvcrt_exit)            }, // _amsg_exit
        { 0x16D9D3F866F577E4, 0xF65F604066C42B11, 0x47229D16ECEF740F, GetFuncAddr(&hook_msvcrt_exit)            }, // _o_exit
        { 0xFA94A3087B0CF593, 0x16E18BF92FFC7C6D, 0x56F78A325866ADC0, GetFuncAddr(&hook_msvcrt_beginthread)     },
        { 0xC2F23D0B4FC3B8A0, 0xD203820C138666FE, 0x33B43D02050237A3, GetFuncAddr(&hook_msvcrt_beginthreadex)   },
        { 0x8FA907505765D71E, 0xDF250DBEE87669C8, 0x28D234843D024582, GetFuncAddr(&hook_msvcrt_endthread)       },
        { 0x48197D982AC1C465, 0x4A0AD7846C848F86, 0x1E6C16857609C0B4, GetFuncAddr(&hook_msvcrt_endthreadex)     },
        { 0xF0266D6BDAB80C6B, 0xD7B26FD9E5DC0B57, 0x2C9BEE6C9FE0D62C, GetFuncAddr(&hook_ucrtbase_p_argc)        },
        { 0xFE18DB4390B76A81, 0xCD56F9696DCE9422, 0x7C587706F08A928B, GetFuncAddr(&hook_ucrtbase_p_argv)        },
        { 0xE0AD5C59F258D5FA, 0x239237030FD8E728, 0xC17DF801E360659F, GetFuncAddr(&hook_ucrtbase_p_wargv)       },
        { 0x784BD5891AC408A0, 0x0874B724BB751530, 0xCB0256E74DAAADF0, GetFuncAddr(&hook_ucrtbase_atexit)        }, // _crt_atexit
        { 0x95D63C89A18BAD5E, 0x5451993245B5FDF4, 0xE2EF082AE19DFCEA, GetFuncAddr(&hook_ucrtbase_atexit)        }, // _crt_at_quick_exit
        { 0xD1E1385A3F0A4A45, 0x6C79AB2137A7C3A0, 0x84F03148C82608E4, GetFuncAddr(&hook_ucrtbase_onexit)        }, // _register_onexit_function
        { 0xC58DD0101399A547, 0xB7098BF88B86C119, 0x6A69D3EF777CE700, GetFuncAddr(&hook_ucrtbase_exit)          },
        { 0x6D909FB9E7C76F50, 0xFC6C332EF63DC28D, 0xCCABF8F3DB3A2870, GetFuncAddr(&hook_ucrtbase_exit)          }, // _exit
        { 0xE7A7E2952F7535CB, 0xEB020582C149E347, 0xA770E93F3FA1C27E, GetFuncAddr(&hook_ucrtbase_exit)          }, // _Exit
        { 0xD7C289DD4E2DD131, 0xD2B801B2689018ED, 0xEAE07DFF7067CBFA, GetFuncAddr(&hook_ucrtbase_exit)          }, // _cexit
        { 0x45DB6DFAC1A803D9, 0x2A52FA2643C355F3, 0x697FE7DF620EF43B, GetFuncAddr(&hook_ucrtbase_exit)          }, // _c_exit
        { 0x9E1CC01FA7A98DC2, 0xD84ECFC6D686E53C, 0xF5264FB60A82D1B3, GetFuncAddr(&hook_ucrtbase_exit)          }, // quick_exit
        { 0x3DDFE8BB76CF95F2, 0xCA790B882EDC59B0, 0x49393C7A4B3907E9, GetFuncAddr(&hook_ucrtbase_beginthread)   },
        { 0x35AABBABC18E5BA3, 0xDD412FBFAE0B41B8, 0xBED389351F41EE45, GetFuncAddr(&hook_ucrtbase_beginthreadex) },
        { 0x076B473DA1B8AA84, 0xC70AD9A8C29A14A3, 0xB15F1F0B74A88CCD, GetFuncAddr(&hook_ucrtbase_endthread)     },
        { 0x165FF801CB2F103A, 0x80DF3DC343C647B9, 0xA011267F33FF69C2, GetFuncAddr(&hook_ucrtbase_endthreadex)   },
    };
#elif _WIN32
    {
        { 0xF0ED49F9, 0x1B54E609, 0x07D295A7, GetFuncAddr(&ldr_GetProcAddress)          },
        { 0x89BEE3E9, 0x06482012, 0x59DC0AFD, GetFuncAddr(&hook_GetCommandLineA)        },
        { 0xB6FAE2CD, 0xD962792E, 0x7D7D98CF, GetFuncAddr(&hook_GetCommandLineW)        },
        { 0x8DE42D3B, 0x34F8EA28, 0x792F03AC, GetFuncAddr(&hook_CommandLineToArgvW)     },
        { 0xEC1638B7, 0x9E73A197, 0x3946430F, GetFuncAddr(&hook_GetStdHandle)           },
        { 0xC702D18B, 0xEEEF6254, 0x75206691, GetFuncAddr(&hook_CreateThread)           },
        { 0xE47A0E89, 0xA7A9BD9B, 0xD34397E1, GetFuncAddr(&hook_ExitThread)             },
        { 0xB9DAB00B, 0x75573886, 0x6DF683FF, GetFuncAddr(&hook_ExitProcess)            },
        { 0x0BE7F3A7, 0xA27772AB, 0x5DBDA851, GetFuncAddr(&hook_ExitThread)             }, // RtlExitUserThread
        { 0x218D28DF, 0xF64F30C5, 0xB32EA5F0, GetFuncAddr(&hook_ExitProcess)            }, // RtlExitUserProcess
        { 0xAA841623, 0x44E5C9F3, 0x816EB549, GetFuncAddr(&hook_msvcrt_getmainargs)     },
        { 0x66A10CA6, 0xA2BA2968, 0xAC17CD10, GetFuncAddr(&hook_msvcrt_wgetmainargs)    },
        { 0x3D3837B6, 0x38694926, 0xD24DA30B, GetFuncAddr(&hook_msvcrt_atexit)          },
        { 0x1EC2BB5F, 0x3DD3B2E3, 0xDDBC367C, GetFuncAddr(&hook_msvcrt_onexit)          },
        { 0x7D7BCDEA, 0xEF475389, 0xE93CCDED, GetFuncAddr(&hook_msvcrt_dllonexit)       },
        { 0xF593B637, 0x924CB533, 0x225EA7B0, GetFuncAddr(&hook_msvcrt_exit)            },
        { 0x74A846F4, 0x03F08899, 0x6D739E11, GetFuncAddr(&hook_msvcrt_exit)            }, // _exit
        { 0xF267020C, 0x32ABCBC5, 0xA8AA1301, GetFuncAddr(&hook_msvcrt_exit)            }, // _Exit
        { 0x54F3FB50, 0x53315825, 0xBD35B97A, GetFuncAddr(&hook_msvcrt_exit)            }, // _cexit
        { 0xBD63617A, 0xDB354F97, 0x3727E4F5, GetFuncAddr(&hook_msvcrt_exit)            }, // _c_exit
        { 0x82BE9EE8, 0x1463DE41, 0xD744D16D, GetFuncAddr(&hook_msvcrt_exit)            }, // quick_exit
        { 0xE7F1D33A, 0x215CF61C, 0xB96553A7, GetFuncAddr(&hook_msvcrt_exit)            }, // _amsg_exit
        { 0xD3C29970, 0x2D2DDBE7, 0xC8D3945F, GetFuncAddr(&hook_msvcrt_exit)            }, // _o_exit
        { 0x0A1B0580, 0xC3EB869F, 0x170D274A, GetFuncAddr(&hook_msvcrt_beginthread)     },
        { 0x870B643B, 0x08CAE98C, 0xE177E5F7, GetFuncAddr(&hook_msvcrt_beginthreadex)   },
        { 0xFD253BB3, 0x400B304B, 0x747B2E73, GetFuncAddr(&hook_msvcrt_endthread)       },
        { 0x0A4C8E15, 0xD522BEE5, 0x7B915AD6, GetFuncAddr(&hook_msvcrt_endthreadex)     },
        { 0xD133074D, 0xDCFD050E, 0x7A843AD5, GetFuncAddr(&hook_ucrtbase_p_argc)        },
        { 0x89FB2177, 0x71EC5A0D, 0x907D1D6A, GetFuncAddr(&hook_ucrtbase_p_argv)        },
        { 0x8296650E, 0x6ADCA7BC, 0xCDF374BB, GetFuncAddr(&hook_ucrtbase_p_wargv)       },
        { 0xB355C6A1, 0xBA600B8E, 0xC2A744E4, GetFuncAddr(&hook_ucrtbase_atexit)        }, // _crt_atexit
        { 0x44859D33, 0x720D5FDC, 0x69637E47, GetFuncAddr(&hook_ucrtbase_atexit)        }, // _crt_at_quick_exit
        { 0x6B79745C, 0xAD509C4E, 0x44F1607E, GetFuncAddr(&hook_ucrtbase_onexit)        }, // _register_onexit_function
        { 0x0C1ED9EA, 0x5A53E5BF, 0x9917A36E, GetFuncAddr(&hook_ucrtbase_exit)          },
        { 0x3CFAB104, 0x5AB8A5F7, 0xF6E42DB4, GetFuncAddr(&hook_ucrtbase_exit)          }, // _exit
        { 0x52B1B9FD, 0x706F8EF0, 0xDF4C49F2, GetFuncAddr(&hook_ucrtbase_exit)          }, // _Exit
        { 0xDFC75191, 0xCD16F1DB, 0xE65BA5BB, GetFuncAddr(&hook_ucrtbase_exit)          }, // _cexit
        { 0x5D0497C6, 0x24B84623, 0x132DD0C1, GetFuncAddr(&hook_ucrtbase_exit)          }, // _c_exit
        { 0xD8D19A14, 0x89087139, 0x116A780E, GetFuncAddr(&hook_ucrtbase_exit)          }, // quick_exit
        { 0xC5BB8743, 0xDF5ECACC, 0x32EF8743, GetFuncAddr(&hook_ucrtbase_beginthread)   },
        { 0x91F0CDA7, 0x405E3C84, 0xC68AFAB8, GetFuncAddr(&hook_ucrtbase_beginthreadex) },
        { 0xBE9DFD88, 0x59F0450D, 0x86063BA9, GetFuncAddr(&hook_ucrtbase_endthread)     },
        { 0x3D6A8336, 0xFB91026B, 0x331FD069, GetFuncAddr(&hook_ucrtbase_endthreadex)   },
    };
#endif
    for (int i = 0; i < arrlen(list); i++)
    {
        hook item  = list[i];
        uint mHash = CalcModHash_W((uint16*)(module), item.hKey);
        if (mHash != item.mHash)
        {
            continue;
        }
        uint pHash = CalcProcHash((byte*)lpProcName, item.hKey);
        if (pHash != item.pHash)
        {
            continue;
        }
        // erase data in the large stack
        mem_init(list, sizeof(list));
        return item.hook;
    }
    // erase data in the large stack
    mem_init(list, sizeof(list));
    return NULL;
}

static errno ldr_init_mutex()
{
    PELoader* loader = getPELoaderPointer();

    // close old status mutex
    if (loader->StatusMu != NULL)
    {
        loader->CloseHandle(loader->StatusMu);
    }
    // create new status mutex
    HANDLE statusMu = loader->CreateMutexA(NULL, false, NAME_LDR_MUTEX_STATUS);
    if (statusMu == NULL)
    {
        return ERR_LOADER_CREATE_MUTEX_STATUS;
    }
    loader->StatusMu = statusMu;
    // lock mutex
#ifndef NO_RUNTIME
    if (!loader->Runtime->Resource.LockMutex(statusMu))
    {
        loader->CloseHandle(statusMu);
        loader->StatusMu = NULL;
        return ERR_LOADER_LOCK_MUTEX_STATUS;
    }
#endif // NO_RUNTIME
    return NO_ERROR;
}

static bool ldr_copy_mapped_image()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (!ldr_lock_status())
    {
        return false;
    }

    // recovery mapped PE image from compressed backup
    // for process section data like ".data"
    void* dst = (void*)(loader->PEImage);
    void* src = loader->PEBackup;
    runtime->Compressor.Decompress(dst, src, loader->PEBackupSize);

    return ldr_unlock_status();
}

__declspec(noinline)
static void* ldr_process_export(LPSTR name)
{
    PELoader* loader = getPELoaderPointer();

    if (name == NULL)
    {
        SetLastErrno(ERR_LOADER_EMPTY_PROC_NAME);
        return NULL;
    }
    uintptr peImage     = loader->PEImage;
    uintptr exportTable = loader->ExportTable;
    uint32  tableSize   = loader->ExportTableSize;
    // check need process export
    if (tableSize == 0)
    {
        SetLastErrno(ERR_LOADER_EMPTY_EXPORT_TABLE);
        return NULL;
    }
    Image_ExportDirectory* export = (Image_ExportDirectory*)(exportTable);
    uint32* funcTable = (uint32*)(peImage + export->AddressOfFunctions);
    uint32* nameTable = (uint32*)(peImage + export->AddressOfNames);
    uint16* ordiTable = (uint16*)(peImage + export->AddressOfNameOrdinals);
    // try to get function RVA
    uint32 funcRVA = 0;
    if (name <= (LPSTR)(0xFFFF))
    {
        // get procedure address by ordinal
        uint16 ordinal = (uint16)(uintptr)name;
        uint32 index   = ordinal - export->Base;
        if (index < export->NumberOfFunctions)
        {
            funcRVA = funcTable[index];
        }
    } else {
        // get procedure address by name
        for (uint32 i = 0; i < export->NumberOfNames; i++)
        {
            LPSTR fn = (LPSTR)(peImage + (uintptr)(nameTable[i]));
            if (!strequ_a(fn, name))
            {
                continue;
            }
            // name[i] -> ordinal[i] -> funcRVA[ordinal]
            funcRVA = funcTable[ordiTable[i]];
            break;
        }
    }
    if (funcRVA == 0)
    {
        SetLastErrno(ERR_LOADER_PROC_NOT_EXIST);
        return NULL;
    }
    // check it is a forwarded export function
    DWORD eatRVA  = (DWORD)(loader->ExportTable-peImage);
    DWORD eatSize = (DWORD)(loader->ExportTableSize);
    if (funcRVA < eatRVA || funcRVA >= eatRVA + eatSize)
    {
        return (void*)(peImage + funcRVA);
    }
    // get the export name
    byte* exportName = (byte*)(peImage + funcRVA);
    // search the last "." in function name
    byte* src = exportName;
    uint  dot = 0;
    for (uint j = 0;; j++)
    {
        byte b = *src;
        if (b == '.')
        {
            dot = j;
        }
        if (b == 0x00)
        {
            break;
        }
        src++;
    }
    // use "mem_init" for prevent incorrect compiler
    // optimize and generate incorrect template
    byte dllName[512];
    mem_init(dllName, sizeof(dllName));
    // prevent array bound when call mem_copy
    if (dot > 500)
    {
        dot = 500;
    }
    mem_copy(dllName, exportName, dot + 1);
    // build DLL name
    dllName[dot+1] = 'd';
    dllName[dot+2] = 'l';
    dllName[dot+3] = 'l';
    dllName[dot+4] = 0x00;
    // load dll if it not loaded
    HMODULE hModule = loader->LoadLibraryA(dllName);
    if (hModule == NULL)
    {
        SetLastErrno(ERR_LOADER_FORWARDED_MODULE);
        return NULL;
    }
    dbg_log("[PE Loader]", "LoadLibrary: %s for forwarded function", dllName);
    // erase data in the large stack
    mem_init(dllName, sizeof(dllName));
    LPCSTR procName = (LPCSTR)((uintptr)exportName + dot + 1);
    return ldr_GetProcAddress(hModule, procName);
}

__declspec(noinline)
static bool ldr_process_import()
{
    PELoader* loader = getPELoaderPointer();

    uintptr peImage     = loader->PEImage;
    uintptr importTable = loader->ImportTable;
    uint32  tableSize   = loader->ImportTableSize;
    // check need process import
    if (tableSize == 0)
    {
        return true;
    }
    // load library and fix function address
    Image_ImportDescriptor* import = (Image_ImportDescriptor*)(importTable);
    for (;;)
    {
        if (import->Name == 0)
        {
            break;
        }
        LPCSTR  dllName = (LPCSTR)(peImage + import->Name);
        HMODULE hModule = loader->LoadLibraryA(dllName);
        if (hModule == NULL)
        {
            if (!loader->Config.AllowSkipDLL)
            {
                return false;
            }
            dbg_log("[PE Loader]", "Skipped Library: %s", dllName);
            import++;
            continue;            
        }
        dbg_log("[PE Loader]", "LoadLibrary: %s", dllName);
        uintptr srcThunk;
        uintptr dstThunk;
        if (import->OriginalFirstThunk != 0)
        {
            srcThunk = peImage + import->OriginalFirstThunk;
        } else {
            srcThunk = peImage + import->FirstThunk; // TODO remove this branch
        }
        dstThunk = peImage + import->FirstThunk;
        // fix function address
        for (;;)
        {
            uintptr value = *(uintptr*)srcThunk;
            if (value == 0)
            {
                break;
            }
            LPCSTR procName;
            if (IMAGE_SNAP_BY_ORDINAL(value))
            {
                procName = (LPCSTR)(value & 0xFFFF);
            } else {
                procName = (LPCSTR)(peImage + value + 2);
            }
            void* proc = ldr_GetProcAddress(hModule, procName);
            if (proc == NULL)
            {
                return false;
            }
            *(uintptr*)dstThunk = (uintptr)proc;
            srcThunk += sizeof(uintptr);
            dstThunk += sizeof(uintptr);
        }
        import++;
    }
    return true;
}

__declspec(noinline)
static bool ldr_process_delay_import()
{
    PELoader* loader = getPELoaderPointer();

    uintptr peImage   = loader->PEImage;
    uintptr dlTable   = loader->DelayImportTable;
    uint32  tableSize = loader->DelayImportTableSize;
    // check need process delay import
    if (tableSize == 0)
    {
        return true;
    }
    Image_DelayloadDescriptor* dld = (Image_DelayloadDescriptor*)(dlTable);
    for (;;)
    {
        if (dld->DllNameRVA == 0)
        {
            break;
        }
        // check the target DLL is loaded
        LPSTR   dllName = (LPSTR)(peImage + dld->DllNameRVA);
        HMODULE hModule = loader->LoadLibraryA(dllName);
        if (hModule == NULL)
        {
            if (!loader->Config.AllowSkipDLL)
            {
                return false;
            }
            dbg_log("[PE Loader]", "Skipped Delay Library: %s", dllName);
            dld++;
            continue;
        }
        dbg_log("[PE Loader]", "Lazy LoadLibrary: %s", dllName);
        Image_ThunkData* nameTable = (Image_ThunkData*)(peImage + dld->ImportNameTableRVA);
        Image_ThunkData* addrTable = (Image_ThunkData*)(peImage + dld->ImportAddressTableRVA);
        Image_ImportByName* ibn;
        for (;;)
        {
            if (nameTable->u1.AddressOfData == 0)
            {
                break;
            }
            LPCSTR procName;
            if (IMAGE_SNAP_BY_ORDINAL(nameTable->u1.Ordinal))
            {
                procName = (LPCSTR)((nameTable->u1.Ordinal) & 0xFFFF);
            } else {
                ibn = (Image_ImportByName*)(peImage + nameTable->u1.AddressOfData);
                procName = (LPCSTR)(ibn->Name);
            }
            void* proc = ldr_GetProcAddress(hModule, procName);
            if (proc == NULL)
            {
                return false;
            }
            addrTable->u1.Function = (QWORD)proc;
            nameTable++;
            addrTable++;
        }
        dld++;
    }
    return true;
}

__declspec(noinline)
static errno ldr_start_process()
{
    PELoader* loader = getPELoaderPointer();

    errno errno = NO_ERROR;
    for (;;)
    {
        if (is_running())
        {
            break;
        }
        errno = ldr_init_mutex();
        if (errno != NO_ERROR)
        {
            break;
        }
        if (!ldr_copy_mapped_image())
        {
            errno = ERR_LOADER_COPY_MAPPED_PE_IMAGE;
            break;
        }
        // load library and fix function address
        if (!ldr_process_import())
        {
            errno = ERR_LOADER_PROCESS_IMPORT;
            break;
        }
        // load library and fix function address
        if (!ldr_process_delay_import())
        {
            errno = ERR_LOADER_PROCESS_DELAY_IMPORT;
            break;
        }
        // reset exit code
        loader->ExitCode = 0;
        // make callback about DLL_PROCESS_DETACH
        if (loader->IsDLL)
        {
            if (!pe_dll_main(DLL_PROCESS_ATTACH, true))
            {
                errno = ERR_LOADER_CALL_DLL_MAIN;
                break;
            }
            set_running(true);
            break;
        }
        // change the running status before create thread
        set_running(true);
        // create thread at entry point
        void* ep = GetFuncAddr(&pe_entry_point);
        HANDLE hThread = loader->CreateThread(NULL, 0, ep, NULL, 0, NULL);
        if (hThread == NULL)
        {
            errno = ERR_LOADER_CREATE_MAIN_THREAD;
            set_running(false);
            break;
        }
        loader->hThread = hThread;
        break;
    }
    return errno;
}

__declspec(noinline)
static void ldr_alloc_tls_block()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (loader->TLSBlock == NULL)
    {
        return;
    }

    // prepare TLS block data memory page
    void* tls = runtime->Memory.Alloc(loader->TLSLen);
    if (tls == NULL)
    {
        return;
    }
    mem_copy(tls, loader->TLSBlock, loader->TLSLen);

    // read the original TLS block address
#ifdef _WIN64
    uintptr* tlsPtr = (uintptr*)(__readgsqword(0x58));
#elif _WIN32
    uintptr* tlsPtr = (uintptr*)(__readfsdword(0x2C));
#endif

    // store the original TLS block address
    uintptr block = *tlsPtr;
    mem_copy(tls, &block, sizeof(block));

    // replace the original TLS block address
    *tlsPtr = (uintptr)tls + 16;

    dbg_log("[PE Loader]", "allocate TLS block: 0x%zX", tls);
}

__declspec(noinline)
static void ldr_free_tls_block()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (loader->TLSBlock == NULL)
    {
        return;
    }

    // read the hooked TLS block address
#ifdef _WIN64
    uintptr* tlsPtr = (uintptr*)(__readgsqword(0x58));
#elif _WIN32
    uintptr* tlsPtr = (uintptr*)(__readfsdword(0x2C));
#endif

    // read the original TLS block address
    void* tls = (void*)(*tlsPtr - 16);

    // restore the original TLS block address
    *tlsPtr = *(uintptr*)tls;

    // free TLS block data
    runtime->Memory.Free(tls);

    dbg_log("[PE Loader]", "free TLS block: 0x%zX", tls);
}

__declspec(noinline)
static void ldr_tls_callback(DWORD dwReason)
{
    PELoader* loader = getPELoaderPointer();

    if (loader->TLSList == NULL)
    {
        return;
    }

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_PROCESS_ATTACH");
        break;
    case DLL_PROCESS_DETACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_PROCESS_DETACH");
        break;
    case DLL_THREAD_ATTACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        dbg_log("[PE Loader]", "call TLS callback with DLL_THREAD_DETACH");
        break;
    }

    TLSCallback_t* list = loader->TLSList;
    while (*list != NULL)
    {
        TLSCallback_t callback = (TLSCallback_t)(*list);
        callback((HMODULE)(loader->PEImage), dwReason, NULL);
        list++;
        dbg_log("[PE Loader]", "call TLS callback: 0x%zX", callback);
    }
}

__declspec(noinline)
static void ldr_register_exit(void* func)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (!ldr_lock_status())
    {
        return;
    }

    // allocate memory for store function pointer
    uint size = sizeof(void*) * (uint)(loader->num_exit + 1);
    loader->on_exit = runtime->Memory.Realloc(loader->on_exit, size);
    // set function pointer
    loader->on_exit[loader->num_exit] = func;
    loader->num_exit++;
    dbg_log("[PE Loader]", "register exit callback: 0x%zX", func);

    ldr_unlock_status();
}

__declspec(noinline)
static void ldr_do_exit()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock_status())
    {
        return;
    }

    int32 num = loader->num_exit;
    for (int32 i = num - 1; i >= 0; i--)
    {
        typedef void(__cdecl *exit_t)();
        exit_t exit = (exit_t)(loader->on_exit[i]);
        exit();
        dbg_log("[PE Loader]", "call exit callback: 0x%zX", exit);
    }

    ldr_unlock_status();
}

static void ldr_exit_process(UINT uExitCode)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "call ldr_exit_process: 0x%zX", uExitCode);

    // process callback about DLL_PROCESS_DETACH
    if (loader->IsDLL)
    {
        pe_dll_main(DLL_PROCESS_DETACH, false);
    }

    if (!runtime->Thread.KillAll())
    {
        dbg_log("[PE Loader]", "failed to kill all threads");
    }

    errno err = runtime->Core.Cleanup();
    if (err != NO_ERROR)
    {
        dbg_log("[PE Loader]", "failed to cleanup: 0x%X", err);
    }

    // Exit or Destroy after call Start()
    if (loader->hThread != NULL)
    {
        loader->CloseHandle(loader->hThread);
        loader->hThread = NULL;
    }

    clean_run_data();
    set_exit_code(uExitCode);
    set_running(false);
}

__declspec(noinline)
LPSTR hook_GetCommandLineA()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "GetCommandLineA");

    // try to get it from config
    LPSTR cmdLine = loader->Config.CommandLineA;
    if (cmdLine != NULL)
    {
        return cmdLine;
    }
    return loader->GetCommandLineA();
}

__declspec(noinline)
LPWSTR hook_GetCommandLineW()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "GetCommandLineW");

    // try to get it from config
    LPWSTR cmdLine = loader->Config.CommandLineW;
    if (cmdLine != NULL)
    {
        return cmdLine;
    }
    return loader->GetCommandLineW();
}

__declspec(noinline)
LPWSTR* hook_CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "CommandLineToArgvW: \"%ls\"", lpCmdLine);

    // find shell32.CommandLineToArgvW
#ifdef _WIN64
    uint mHash = 0x1CD9EC250616E109;
    uint pHash = 0xB19CBAA302673FE9;
    uint hKey  = 0xB4B882421FE62D1F;
#elif _WIN32
    uint mHash = 0x5DAFEDFC;
    uint pHash = 0xBED6046A;
    uint hKey  = 0x7A08154B;
#endif
    CommandLineToArgvW_t CommandLineToArgvW = runtime->HashAPI.FindAPI_MH(mHash, pHash, hKey);
    if (CommandLineToArgvW == NULL)
    {
        return NULL;
    }

    // if lpCmdLine is not L"", call the original function
    uint16 empty[] = { 0x0000 };
    if (!strequ_w((UTF16)lpCmdLine, empty))
    {
        return CommandLineToArgvW(lpCmdLine, pNumArgs);
    }

    LPWSTR cmdLine = hook_GetCommandLineW();
    return CommandLineToArgvW(cmdLine, pNumArgs);
}

__declspec(noinline)
HANDLE hook_GetStdHandle(DWORD nStdHandle)
{
    PELoader* loader = getPELoaderPointer();

    // try to get it from config
    HANDLE hStdInput  = loader->Config.StdInput;
    HANDLE hStdOutput = loader->Config.StdOutput;
    HANDLE hStdError  = loader->Config.StdError;

    switch (nStdHandle)
    {
    case STD_INPUT_HANDLE:
        if (hStdInput != NULL)
        {
            dbg_log("[PE Loader]", "Get STD_INPUT_HANDLE");
            return hStdInput;
        }
        break;
    case STD_OUTPUT_HANDLE:
        if (hStdOutput != NULL)
        {
            dbg_log("[PE Loader]", "Get STD_OUTPUT_HANDLE");
            return hStdOutput;
        }
        break;
    case STD_ERROR_HANDLE:
        if (hStdError != NULL)
        {
            dbg_log("[PE Loader]", "Get STD_ERROR_HANDLE");
            return hStdError;
        }
        break;
    }
    return loader->GetStdHandle(nStdHandle);
}

// about calling convention for msvcrt/ucrtbase._beginthread
#define CC_STDCALL 0
#define CC_CDECL   1
#define CC_CLRCALL 2

typedef struct {
    POINTER lpStartAddress;
    LPVOID  lpParameter;
    DWORD   callConvention;
} createThreadCtx;

__declspec(noinline)
HANDLE hook_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId
){
    return stub_CreateThread(
        lpThreadAttributes, dwStackSize, lpStartAddress,
        lpParameter, dwCreationFlags, lpThreadId, CC_STDCALL
    );
}

__declspec(noinline)
HANDLE stub_CreateThread(
    POINTER lpThreadAttributes, SIZE_T dwStackSize, POINTER lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, DWORD* lpThreadId, DWORD cc
){
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "CreateThread: 0x%zX", lpStartAddress);

    // alloc memory for store actual StartAddress and Parameter
    uint size = sizeof(createThreadCtx);
    size += (1 + runtime->Random.UintN(0, 4)) * 4096;
    LPVOID parameter = runtime->Memory.Alloc(size);
    if (parameter == NULL)
    {
        return NULL;
    }

    createThreadCtx* ctx = (createThreadCtx*)parameter;
    ctx->lpStartAddress = lpStartAddress;
    ctx->lpParameter    = lpParameter;
    ctx->callConvention = cc;

    // create thread at stub, that function will call actual StartAddress
    void* addr = GetFuncAddr(&stub_ExecuteThread);
    HANDLE hThread = loader->CreateThread
    (
        lpThreadAttributes, dwStackSize, addr,
        parameter, dwCreationFlags, lpThreadId
    );
    return hThread;
}

__declspec(noinline)
void stub_ExecuteThread(LPVOID lpParameter)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    // copy arguments from context 
    createThreadCtx* ctx = (createThreadCtx*)lpParameter;
    POINTER startAddress   = ctx->lpStartAddress;
    LPVOID  parameter      = ctx->lpParameter;
    DWORD   callConvention = ctx->callConvention;
    runtime->Memory.Free(lpParameter);

    // execute TLS callback list before call dll_main.
    ldr_alloc_tls_block();
    ldr_tls_callback(DLL_THREAD_ATTACH);

    if (loader->IsDLL)
    {
        pe_dll_main(DLL_THREAD_ATTACH, false);
    }

    // execute the function
    switch (callConvention)
    {
    case CC_STDCALL:
      {
        typedef void(__stdcall *fep_t)(LPVOID lpParameter);
        fep_t ep = (fep_t)startAddress;
        ep(parameter);
        break;
      }
    case CC_CDECL:
      {
        typedef void (__cdecl *fep_t)(LPVOID lpParameter);
        fep_t ep = (fep_t)startAddress;
        ep(parameter);
        break;
      }
    case CC_CLRCALL:
      {
        // TODO think it  __clrcall
        typedef void(__stdcall *fep_t)(LPVOID lpParameter);
        fep_t ep = (fep_t)startAddress;
        ep(parameter);
        break;
      }
    default:
        panic(PANIC_UNREACHABLE_CODE);
    }

    hook_ExitThread(0);
}

__declspec(noinline)
void hook_ExitThread(DWORD dwExitCode)
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "ExitThread: %d", dwExitCode);

    if (loader->IsDLL)
    {
        pe_dll_main(DLL_THREAD_DETACH, false);
    }

    // execute TLS callback list after call dll_main.
    ldr_tls_callback(DLL_THREAD_DETACH);
    ldr_free_tls_block();

    loader->ExitThread(dwExitCode);
}

__declspec(noinline)
void hook_ExitProcess(UINT uExitCode)
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "ExitProcess: %zu", uExitCode);

    if (!runtime->Thread.KillAll())
    {
        dbg_log("[PE Loader]", "failed to kill all threads");
    }

    // execute TLS callback list befor call ExitThread.
    ldr_tls_callback(DLL_PROCESS_DETACH);
    ldr_free_tls_block();

    errno err = runtime->Core.Cleanup();
    if (err != NO_ERROR)
    {
        dbg_log("[PE Loader]", "failed to cleanup: 0x%X", err);
    }

    clean_run_data();
    set_exit_code(uExitCode);
    set_running(false);

    if (loader->Config.WaitMain || loader->Config.NotStopRuntime)
    {
        loader->ExitThread(0);
        return;
    }

    if (!runtime->Watchdog.IsEnabled() || uExitCode == 0)
    {
        runtime->Core.Stop(uExitCode);
        return;
    }
    loader->ExitThread(0);
}

__declspec(noinline)
int __cdecl hook_msvcrt_getmainargs(
    int* argc, byte*** argv, byte*** env, int doWildCard, void* startInfo
){
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "call msvcrt.__getmainargs");

    // find msvcrt.__getmainargs
#ifdef _WIN64
    uint mHash = 0x52CEA62C2AF4F9C6;
    uint pHash = 0x9F08687311B2AC6F;
    uint hKey  = 0x2A4C6C7B39CC674F;
#elif _WIN32
    uint mHash = 0x67E36D1C;
    uint pHash = 0xC4AC5444;
    uint hKey  = 0xADAA4C44;
#endif
    msvcrt_getmainargs_t getmainargs = runtime->HashAPI.FindAPI_MH(mHash, pHash, hKey);
    if (getmainargs == NULL)
    {
        return -1;
    }

    // call original function to process other arguments,
    // argv and env must NOT free, it allocated by msvcrt
    int ret = getmainargs(argc, argv, env, doWildCard, startInfo);
    if (ret == -1)
    {
        return ret;
    }

    // hijack the return value about argc and argv
    loadCommandLineToArgv();
    if (loader->argc != 0)
    {
        *argc = loader->argc;
        *argv = loader->argv_a;
    }
    return ret;
}

__declspec(noinline)
int __cdecl hook_msvcrt_wgetmainargs(
    int* argc, uint16*** argv, uint16*** env, int doWildCard, void* startInfo
){
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "call msvcrt.__wgetmainargs");

    // find msvcrt.__wgetmainargs
#ifdef _WIN64
    uint mHash = 0xBC73780240DAAD3C;
    uint pHash = 0x5615F23FC8EB535B;
    uint hKey  = 0x005B0A6FCD5A1154;
#elif _WIN32
    uint mHash = 0xFD695257;
    uint pHash = 0x6AC316B4;
    uint hKey  = 0xBAAA7F84;
#endif
    msvcrt_wgetmainargs_t wgetmainargs = runtime->HashAPI.FindAPI_MH(mHash, pHash, hKey);
    if (wgetmainargs == NULL)
    {
        return -1;
    }

    // call original function to process other arguments,
    // argv and env must NOT free, it allocated by msvcrt
    int ret = wgetmainargs(argc, argv, env, doWildCard, startInfo);
    if (ret == -1)
    {
        return ret;
    }

    // hijack the return value about argc and argv
    loadCommandLineToArgv();
    if (loader->argc != 0)
    {
        *argc = loader->argc;
        *argv = loader->argv_w;
    }
    return ret;
}

__declspec(noinline)
int __cdecl hook_msvcrt_atexit(void* func)
{
    dbg_log("[PE Loader]", "call msvcrt.atexit");
    ldr_register_exit(func);
    return 0;
}

__declspec(noinline)
void* __cdecl hook_msvcrt_onexit(void* func)
{
    dbg_log("[PE Loader]", "call msvcrt._onexit");
    ldr_register_exit(func);
    return func;
}

__declspec(noinline)
void* __cdecl hook_msvcrt_dllonexit(void* func, void* pbegin, void* pend)
{
    dbg_log("[PE Loader]", "call msvcrt._dllonexit");
    ldr_register_exit(func);
    // ignore warning
    pbegin = NULL;
    pend   = NULL;
    return func;
}

__declspec(noinline)
void __cdecl hook_msvcrt_exit(int exitcode)
{
    dbg_log("[PE Loader]", "call msvcrt.exit");
    ldr_do_exit();
    hook_ExitProcess((UINT)exitcode);
}

__declspec(noinline)
uint __cdecl hook_msvcrt_beginthread(
    void* proc, uint32 stackSize, void* arg
){
    dbg_log("[PE Loader]", "call msvcrt._beginthread");
    HANDLE hThread = stub_CreateThread(
        0, stackSize, proc, arg, 0, NULL, CC_CDECL
    );
    return (uint)hThread;
}

__declspec(noinline)
uint __cdecl hook_msvcrt_beginthreadex(
    void* security, uint32 stackSize, void* proc, 
    void* arg, uint32 flag, uint32* tid
){
    dbg_log("[PE Loader]", "call msvcrt._beginthreadex");
    HANDLE hThread = stub_CreateThread(
        security, stackSize, proc, arg, flag, tid, CC_STDCALL
    );
    return (uint)hThread;
}

__declspec(noinline)
void __cdecl hook_msvcrt_endthread()
{
    dbg_log("[PE Loader]", "call msvcrt._endthread");
    hook_ExitThread(0);
}

__declspec(noinline)
void __cdecl hook_msvcrt_endthreadex(uint32 code)
{
    dbg_log("[PE Loader]", "call msvcrt._endthreadex");
    hook_ExitThread(code);
}

__declspec(noinline)
int* __cdecl hook_ucrtbase_p_argc()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "call ucrtbase.__p___argc");

    loadCommandLineToArgv();
    if (loader->argc != 0)
    {
        return &loader->argc;
    }

    // call ucrtbase.__p___argc
#ifdef _WIN64
    uint mHash = 0x8C3BFA3A3E1F6AE2;
    uint pHash = 0x9944C3FD882C3E13;
    uint hKey  = 0xEFC1321D1BE46BB7;
#elif _WIN32
    uint mHash = 0xB094C19D;
    uint pHash = 0x80842212;
    uint hKey  = 0xAF4827C9;
#endif
    ucrtbase_p_argc_t p_argc = runtime->HashAPI.FindAPI_MH(mHash, pHash, hKey);
    if (p_argc == NULL)
    {
        return NULL;
    }
    return p_argc();
}

__declspec(noinline)
byte*** __cdecl hook_ucrtbase_p_argv()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "call ucrtbase.__p___argv");

    loadCommandLineToArgv();
    if (loader->argc != 0)
    {
        return &loader->argv_a;
    }

    // call ucrtbase.__p___argv
#ifdef _WIN64
    uint mHash = 0x76331E01239D4039;
    uint pHash = 0x4C4B4C56BC8E96F6;
    uint hKey  = 0x5E0CC8B43919F3E1;
#elif _WIN32
    uint mHash = 0x0BD54317;
    uint pHash = 0x64472B0D;
    uint hKey  = 0x9D9FB3CF;
#endif
    ucrtbase_p_argv_t p_argv = runtime->HashAPI.FindAPI_MH(mHash, pHash, hKey);
    if (p_argv == NULL)
    {
        return NULL;
    }
    return p_argv();
}

__declspec(noinline)
uint16*** __cdecl hook_ucrtbase_p_wargv()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    dbg_log("[PE Loader]", "call ucrtbase.__p___wargv");

    loadCommandLineToArgv();
    if (loader->argc != 0)
    {
        return &loader->argv_w;
    }

    // call ucrtbase.__p___wargv
#ifdef _WIN64
    uint mHash = 0xD70662821E221E17;
    uint pHash = 0x8D749DE0FA1813FB;
    uint hKey  = 0xE329CFBFBB074BC1;
#elif _WIN32
    uint mHash = 0x932A1B6B;
    uint pHash = 0xD61A0370;
    uint hKey  = 0x8F33ADE7;
#endif
    ucrtbase_p_wargv_t p_wargv = runtime->HashAPI.FindAPI_MH(mHash, pHash, hKey);
    if (p_wargv == NULL)
    {
        return NULL;
    }
    return p_wargv();
}

__declspec(noinline)
int __cdecl hook_ucrtbase_atexit(void* func)
{
    dbg_log("[PE Loader]", "call ucrtbase._crt_atexit");
    ldr_register_exit(func);
    return 0;
}

__declspec(noinline)
int __cdecl hook_ucrtbase_onexit(void* table, void* func)
{
    dbg_log("[PE Loader]", "call ucrtbase._register_onexit_function");
    ldr_register_exit(func);
    // ignore warning
    table = NULL;
    return 0;
}

__declspec(noinline)
void __cdecl hook_ucrtbase_exit(int exitcode)
{
    dbg_log("[PE Loader]", "call ucrtbase.exit");
    ldr_do_exit();
    hook_ExitProcess((UINT)exitcode);
}

__declspec(noinline)
uint __cdecl hook_ucrtbase_beginthread(
    void* proc, uint32 stackSize, void* arg
){
    dbg_log("[PE Loader]", "call ucrtbase._beginthread");
    HANDLE hThread = stub_CreateThread(
        0, stackSize, proc, arg, 0, NULL, CC_CDECL
    );
    return (uint)hThread;
}

__declspec(noinline)
uint __cdecl hook_ucrtbase_beginthreadex(
    void* security, uint32 stackSize, void* proc, 
    void* arg, uint32 flag, uint32* tid
){
    dbg_log("[PE Loader]", "call ucrtbase._beginthreadex");
    HANDLE hThread = stub_CreateThread(
        security, stackSize, proc, arg, flag, tid, CC_STDCALL
    );
    return (uint)hThread;
}

__declspec(noinline)
void __cdecl hook_ucrtbase_endthread()
{
    dbg_log("[PE Loader]", "call ucrtbase._endthread");
    hook_ExitThread(0);
}

__declspec(noinline)
void __cdecl hook_ucrtbase_endthreadex(uint32 code)
{
    dbg_log("[PE Loader]", "call ucrtbase._endthreadex");
    hook_ExitThread(code);
}

// if you only parse the command line parameters in the configuration
// and not the current process, the size of the hook function will 
// be larger, but if there are no command line parameters in the 
// configuration, you can use the internal implementation in msvcrt 
// or ucrtbase instead of loading shell32.dll.
void loadCommandLineToArgv()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (loader->argc != 0)
    {
        return;
    }

    LPWSTR cmdLine = loader->Config.CommandLineW;
    if (cmdLine == NULL)
    {
        return;
    }

    // make sure shell32.dll is loaded
    byte dllName[] = {
        's', 'h', 'e', 'l', 'l', '3', '2', 
        '.', 'd', 'l', 'l', '\x00'
    };
    HMODULE hShell32 = loader->LoadLibraryA(dllName);
    if (hShell32 == NULL)
    {
        return;
    }

    int argc = 0;
    LPWSTR* argv;
    for (;;)
    {
        argv = hook_CommandLineToArgvW(cmdLine, &argc);
        if (argv == NULL)
        {
            break;
        }
        dbg_log("[PE Loader]", "argv pointer: 0x%zX", argv);

        // calculate the buffer size about argv
        // add size of pointer array
        uint size = ((uint)argc + 1) * sizeof(LPWSTR);
        // add each argument string length
        for (LPWSTR* p = argv; *p != NULL; p++)
        {
            size += (strlen_w(*p) + 1) * 2;
        }

        // copy buffer data that we can hide it
        // otherwise, it will in the local heap
        LPWSTR* argv_a = runtime->Memory.Alloc(size);
        LPWSTR* argv_w = runtime->Memory.Alloc(size);
        mem_copy(argv_a, argv, size);
        mem_copy(argv_w, argv, size);

        // fix the string pointers
        uintptr offset = (uintptr)argv_a - (uintptr)argv;
        for (LPWSTR* p = argv_a; *p != NULL; p++)
        {
            uintptr addr = (uintptr)(*p) + offset;
            *p = (LPWSTR)addr;
        }
        offset = (uintptr)argv_w - (uintptr)argv;
        for (LPWSTR* p = argv_w; *p != NULL; p++)
        {
            uintptr addr = (uintptr)(*p) + offset;
            *p = (LPWSTR)addr;
        }

        // convert each argument from UTF16 to ANSI for argv_a
        for (LPWSTR* p = argv_a; *p != NULL; p++)
        {
            LPWSTR ptr = *p;
            ANSI s = runtime->WinBase.UTF16ToANSI(ptr);
            if (s == NULL)
            {
                break;
            }
            strcpy_a((ANSI)ptr, s);
            runtime->Memory.Free(s);
        }
        LPSTR* argv_n = (LPSTR*)argv_a;

        loader->argc   = argc;
        loader->argv_a = argv_n;
        loader->argv_w = argv_w;
        break;
    }

    // free memory from CommandLineToArgvW
    if (argv != NULL)
    {
        loader->LocalFree(argv);
    }
    loader->FreeLibrary(hShell32);
}

__declspec(noinline)
static void pe_entry_point()
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call entry point");

    // execute TLS callback list before call EntryPoint.
    ldr_alloc_tls_block();
    ldr_tls_callback(DLL_PROCESS_ATTACH);

    // call EntryPoint usually is main.
    uint exitCode = ((uint(*)())(loader->EntryPoint))();

    // exit process
    hook_ExitProcess((UINT)exitCode);
}

__declspec(noinline)
static bool pe_dll_main(DWORD dwReason, bool setExitCode)
{
    PELoader* loader = getPELoaderPointer();

    dbg_log("[PE Loader]", "call DllMain with reason: %d", dwReason);

    // call dll main function
    DllMain_t dllMain = (DllMain_t)(loader->EntryPoint);
    HMODULE   hModule = (HMODULE)(loader->PEImage);
    bool retval = dllMain(hModule, dwReason, NULL);
    uint exitCode;
    if (retval)
    {
        exitCode = 0;
    } else {
        exitCode = 1;
    }
    if (setExitCode)
    {
        set_exit_code(exitCode);
    }
    return retval;
}

static void set_exit_code(uint code)
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock_status())
    {
        return;
    }

    loader->ExitCode = code;

    ldr_unlock_status();
}

__declspec(noinline)
static void set_running(bool run)
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock_status())
    {
        return;
    }

    loader->IsRunning = run;

    ldr_unlock_status();
}

__declspec(noinline)
static bool is_running()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock_status())
    {
        return false;
    }

    bool running = loader->IsRunning;

    if (!ldr_unlock_status())
    {
        return false;
    }
    return running;
}

__declspec(noinline)
static void clean_run_data()
{
    PELoader* loader = getPELoaderPointer();

    // reset command line arguments
    loader->argc   = 0;
    loader->argv_a = NULL;
    loader->argv_w = NULL;

    // reset on exit callback
    loader->on_exit  = NULL;
    loader->num_exit = 0;
}

__declspec(noinline)
static void reset_handler()
{
    PELoader* loader = getPELoaderPointer();

    void*  address = GetFuncAddr(&restart_image);
    HANDLE hThread = loader->CreateThread(NULL, 0, address, NULL, 0, NULL);
    if (hThread == NULL)
    {
        return;
    }
    loader->CloseHandle(hThread);
}

__declspec(noinline)
static uint restart_image()
{
    dbg_log("[PE Loader]", "restart PE image");

    errno errno = LDR_Exit(0);
    if (errno != NO_ERROR)
    {
        dbg_log("[PE Loader]", "failed to exit PE image: 0x%X", errno);
    }

    // make sure the running data is clean
    clean_run_data();

    errno = LDR_Execute();
    if (errno != NO_ERROR)
    {
        dbg_log("[PE Loader]", "unexpected exit code: 0x%X", errno);
    }
    return 0;
}

__declspec(noinline)
void* LDR_GetProc(byte* name)
{
    if (!ldr_lock())
    {
        SetLastErrno(ERR_LOADER_LOCK);
        return NULL;
    }

    void* address = NULL;
    for (;;)
    {
        if (!is_running())
        {
            SetLastErrno(ERR_LOADER_NOT_RUNNING);
            break;
        }
        address = ldr_process_export(name);
        break;
    }

    if (!ldr_unlock())
    {
        SetLastErrno(ERR_LOADER_UNLOCK);
        return NULL;
    }
    return address;
}

__declspec(noinline)
uint LDR_ExitCode()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock())
    {
        return (uint)(-2);
    }

    if (!ldr_lock_status())
    {
        return (uint)(-2);
    }
    uint code = loader->ExitCode;
    if (!ldr_unlock_status())
    {
        return (uint)(-2);
    }

    if (!ldr_unlock())
    {
        return (uint)(-2);
    }
    return code;
}

__declspec(noinline)
errno LDR_Start()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    errno errno = NO_ERROR;
    for (;;)
    {
        if (loader->IsDLL)
        {
            errno = ERR_LOADER_NOT_EXE_IMAGE;
            break;
        }
        errno = ldr_start_process();
        break;
    }

    if (!ldr_unlock())
    {
        return ERR_LOADER_UNLOCK;
    }
    return errno;
}

__declspec(noinline)
errno LDR_Wait()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    HANDLE hThread = NULL;
    errno  errno   = NO_ERROR;
    for (;;)
    {
        if (loader->IsDLL)
        {
            errno = ERR_LOADER_NOT_EXE_IMAGE;
            break;
        }
        if (!is_running())
        {
            errno = ERR_LOADER_PROCESS_IS_NOT_START;
            break;
        }
        hThread = loader->hThread;
        loader->hThread = NULL;
        break;
    }

    if (!ldr_unlock())
    {
        return ERR_LOADER_UNLOCK;
    }

    if (errno != NO_ERROR)
    {
        return errno;
    }
    loader->WaitForSingleObject(hThread, INFINITE);
    loader->CloseHandle(hThread);
    return NO_ERROR;
}

__declspec(noinline)
errno LDR_Execute()
{
    PELoader* loader = getPELoaderPointer();

    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    HANDLE hThread = NULL;
    errno  errno   = NO_ERROR;
    for (;;)
    {
        errno = ldr_start_process();
        if (errno != NO_ERROR)
        {
            break;
        }
        hThread = loader->hThread;
        loader->hThread = NULL;
        break;
    }

    if (!ldr_unlock())
    {
        return ERR_LOADER_UNLOCK;
    }

    if (errno != NO_ERROR)
    {
        return errno;
    }

    // wait main thread exit
    if (loader->Config.WaitMain)
    {
        loader->WaitForSingleObject(hThread, INFINITE);
        set_running(false);
    }
    loader->CloseHandle(hThread);
    return NO_ERROR;
}

__declspec(noinline)
errno LDR_Exit(uint32 exitCode)
{
    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    if (is_running())
    {
        ldr_exit_process(exitCode);
    }

    if (!ldr_unlock())
    {
        return ERR_LOADER_UNLOCK;
    }
    return NO_ERROR;
}

__declspec(noinline)
errno LDR_Destroy()
{
    PELoader*  loader  = getPELoaderPointer();
    Runtime_M* runtime = loader->Runtime;

    if (!ldr_lock())
    {
        return ERR_LOADER_LOCK;
    }

    if (is_running())
    {
        ldr_exit_process((uint)(-1));
    }

    errno error = NO_ERROR;
    errno errcl = cleanPELoader(loader);
    if (errcl != NO_ERROR && error == NO_ERROR)
    {
        error = errcl;
    }
    errno errex = runtime->Core.Exit();
    if (errex != NO_ERROR && error == NO_ERROR)
    {
        error = errex;
    }
    return error;
}

// prevent it be linked to other functions.
#pragma optimize("", off)

// make sure these function is large than 12 bytes
#pragma warning(push)
#pragma warning(disable: 4189)
static void ldr_pointer_stub()
{
    uint64 var = 0xFFFFFFFFFFFFFFFF;
}

static void ldr_epilogue()
{
    byte var = 10;
    return;
}
#pragma warning(pop)

#pragma optimize("", on)
