@echo off

echo ====================================================================
echo Build HashAPI tool from https://github.com/RTS-Framework/GRT-Develop
echo ====================================================================
echo.

echo ------------------------x64------------------------

echo [PE-Loader Core]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualAlloc
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualFree
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc VirtualProtect
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LoadLibraryA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FreeLibrary
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetProcAddress
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ExitThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc FlushInstructionCache
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateMutexA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ReleaseMutex
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc WaitForSingleObject
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateFileA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CloseHandle
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetCommandLineA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetCommandLineW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc LocalFree
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetStdHandle
echo.

echo [PE-Loader Hooks]
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetProcAddress
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetCommandLineA
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetCommandLineW
hash_api -fmt 64 -conc -mod "shell32.dll"  -proc CommandLineToArgvW
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc GetStdHandle
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc CreateThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ExitThread
hash_api -fmt 64 -conc -mod "kernel32.dll" -proc ExitProcess
hash_api -fmt 64 -conc -mod "ntdll.dll"    -proc RtlExitUserThread
hash_api -fmt 64 -conc -mod "ntdll.dll"    -proc RtlExitUserProcess
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc __getmainargs
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc __wgetmainargs
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc atexit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _onexit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _dllonexit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _Exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _cexit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _c_exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc quick_exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _amsg_exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _o_exit
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _beginthread
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _beginthreadex
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _endthread
hash_api -fmt 64 -conc -mod "msvcrt.dll"   -proc _endthreadex
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc __p___argc
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc __p___argv
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc __p___wargv
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _crt_atexit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _crt_at_quick_exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _register_onexit_function
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _Exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _cexit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _c_exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc quick_exit
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _beginthread
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _beginthreadex
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _endthread
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc _endthreadex
echo.

echo [PE-Loader Misc]
hash_api -fmt 64 -conc -mod "shell32.dll" -proc CommandLineToArgvW

hash_api -fmt 64 -conc -mod "msvcrt.dll" -proc __getmainargs
hash_api -fmt 64 -conc -mod "msvcrt.dll" -proc __wgetmainargs

hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc __p___argc
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc __p___argv
hash_api -fmt 64 -conc -mod "ucrtbase.dll" -proc __p___wargv
echo.

echo ------------------------x86------------------------

echo [PE-Loader Core]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualAlloc
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualFree
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc VirtualProtect
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LoadLibraryA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FreeLibrary
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetProcAddress
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ExitThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc FlushInstructionCache
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateMutexA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ReleaseMutex
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc WaitForSingleObject
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateFileA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CloseHandle
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetCommandLineA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetCommandLineW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc LocalFree
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetStdHandle
echo.

echo [PE-Loader Hooks]
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetProcAddress
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetCommandLineA
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetCommandLineW
hash_api -fmt 32 -conc -mod "shell32.dll"  -proc CommandLineToArgvW
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc GetStdHandle
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc CreateThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ExitThread
hash_api -fmt 32 -conc -mod "kernel32.dll" -proc ExitProcess
hash_api -fmt 32 -conc -mod "ntdll.dll"    -proc RtlExitUserThread
hash_api -fmt 32 -conc -mod "ntdll.dll"    -proc RtlExitUserProcess
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc __getmainargs
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc __wgetmainargs
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc atexit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _onexit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _dllonexit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _Exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _cexit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _c_exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc quick_exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _amsg_exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _o_exit
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _beginthread
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _beginthreadex
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _endthread
hash_api -fmt 32 -conc -mod "msvcrt.dll"   -proc _endthreadex
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc __p___argc
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc __p___argv
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc __p___wargv
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _crt_atexit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _crt_at_quick_exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _register_onexit_function
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _Exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _cexit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _c_exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc quick_exit
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _beginthread
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _beginthreadex
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _endthread
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc _endthreadex
echo.

echo [PE-Loader Misc]
hash_api -fmt 32 -conc -mod "shell32.dll" -proc CommandLineToArgvW

hash_api -fmt 32 -conc -mod "msvcrt.dll" -proc __getmainargs
hash_api -fmt 32 -conc -mod "msvcrt.dll" -proc __wgetmainargs

hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc __p___argc
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc __p___argv
hash_api -fmt 32 -conc -mod "ucrtbase.dll" -proc __p___wargv
echo.

pause
