#ifndef DEBUG_H
#define DEBUG_H

#include "build.h"
#include "c_types.h"

#ifdef ENABLE_DEBUGGER
  #ifdef _WIN64
    #define NAME_LDR_MUTEX_GLOBAL "x64_LDR_Global"
    #define NAME_LDR_MUTEX_STATUS "x64_LDR_Status"
  #elif _WIN32
    #define NAME_LDR_MUTEX_GLOBAL "x86_LDR_Global"
    #define NAME_LDR_MUTEX_STATUS "x86_LDR_Status"
  #endif
#else
    #define NAME_LDR_MUTEX_GLOBAL NULL
    #define NAME_LDR_MUTEX_STATUS NULL
#endif // ENABLE_DEBUGGER

#ifdef ENABLE_DEBUGGER

bool InitDebugger();

void dbg_lock();
void dbg_unlock();

void dbg_log(char* mod, char* fmt, ...);

#else

#define InitDebugger() (true)

#define dbg_lock()
#define dbg_unlock()

#define dbg_log(mod, fmt, ...)

#endif // ENABLE_DEBUGGER

#endif // DEBUG_H
