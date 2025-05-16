#include <windows.h>

#include "beacon.h"
#include "dllmain.h"
#include "macros.h"
#include "pipes.h"
#include "utils.h"

/**
* Initialize the postex DLL.
*
* @param postexData A pointer to a POSTEX_DATA structure containing user-definable postex data
*/
BOOL PostexInit(PPOSTEX_DATA postexData) {
    RETURN_FALSE_ON_NULL(postexData);

    // Check whether to cleanup the loader (See comment in DebugEntryPoint()).
    if (postexData->PostexArguments->CleanupLoader > 0) {
        /**
        * Note: as part of this template, we "cleanup" the memory we allocated
        * in DebugMain() to replicate a postex loader. In "Release", this 
        * is the loader memory.
        */
        CleanupLoaderMemory(postexData->PostexLoaderBaseAddress);
    }
    // Start named pipe server
    if (postexData->StartNamedPipe) {
        StartNamedPipeServer();
    }

    return TRUE;
}

/**
* Exit the postex DLL.
*
* @param postexData A pointer to a POSTEX_DATA structure containing user-definable postex data
*/
void PostexExit(PPOSTEX_DATA postexData) {
    RETURN_ON_NULL(postexData);
    // Disconnect pipe, close handle and exit
    if (postexData->StartNamedPipe) {
        StopNamedPipeServer();
    }

    //Check how to exit
    if (postexData->PostexArguments->ExitFunc == EXITFUNC_THREAD) {
        ExitThread(0);
    }
    else if (postexData->PostexArguments->ExitFunc == EXITFUNC_PROCESS) {
        ExitProcess(0);
    }
    return;
}

/**
* Cleanup the postex loader memory.
* 
* @param loaderBaseAddress A pointer to the base address of the injected postex loader
* 
* @return A Boolean value to indicate success
*/
BOOL CleanupLoaderMemory(char* loaderBaseAddress) {
    RETURN_FALSE_ON_NULL(loaderBaseAddress);
    MEMORY_BASIC_INFORMATION loaderMemoryInformation = {0};
    if (VirtualQuery(loaderBaseAddress, &loaderMemoryInformation, sizeof(MEMORY_BASIC_INFORMATION))) {
        if (loaderMemoryInformation.RegionSize > 0) {
            if (loaderMemoryInformation.Type == MEM_PRIVATE) {
                return VirtualFree(loaderMemoryInformation.BaseAddress, 0, MEM_RELEASE);
            }
            else if (loaderMemoryInformation.Type == MEM_MAPPED) {
                return UnmapViewOfFile(loaderBaseAddress);
            }
        }
    }    
    return FALSE;
}
