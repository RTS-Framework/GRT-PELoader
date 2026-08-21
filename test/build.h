#ifndef BUILD_H
#define BUILD_H

#define TEST_MODE

// ENABLE_DEBUGGER:  enable debugger module for test and debug
// DISABLE_PIC_MODE: run unit tests under .text instance
// NO_RUNTIME:       not include Gleam-RT for test and debug

// #define ENABLE_DEBUGGER
// #define DISABLE_PIC_MODE
// #define NO_RUNTIME

// if enable debugger, must disable pic mode
#ifdef ENABLE_DEBUGGER
  #define DISABLE_PIC_MODE
#endif

// disable special warnings for NO_RUNTIME
#ifdef NO_RUNTIME
    #pragma warning(disable: 4100)
    #pragma warning(disable: 4189)
#endif

#endif // BUILD_H
