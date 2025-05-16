#ifdef _DEBUG
#include <windows.h>

#include "beacon.h"
#include "dllmain.h"
#include "macros.h"
#include "mock.h"
#include "utils.h"

/**
* A debug entrypoint function to replicate some of the functions of the postex loader
* and the CS client.
*
* @param userArgumentBuffer A pointer to a mock argument buffer
* @oaram userArgumentBufferSize The size of the mock argument buffer
* @param startNamedPipe A boolean value to indicate whether the named pipe server should be started
*/
void DebugEntryPoint(char* userArgumentBuffer, int userArgumentBufferSize, BOOL startNamedPipe) {
    /**
    * Allocate some memory to replicate the postex loader memory
    *
    * Note: Change this to match the way your loader is allocated
    */
    char* placeholderLoaderMemory = reinterpret_cast<char*>(VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (placeholderLoaderMemory != NULL) {
        // Write "postexloader" to the allocation for clarity
        char postexString[] = "postexloader";
        for (size_t i = 0; i < 4096; i++) {
            placeholderLoaderMemory[i] = postexString[i % sizeof(postexString)];
        }
    }

    /* 
    * "Stomp" the postex arguments structure.
    * This is to replicate the way the CS client stomps the malleable C2 config and
    * the size of the argument buffer into the DLL as it is sent to Beacon.
    * 
    * Note: The value given to CleanupLoader here is 'Y' for
    * "Yes" but the CS client will actually stomp a random positive value
    * into this location. As a result, any tests should be kept to
    * CleanupLoader > 0.
    */
    reinterpret_cast<volatile POSTEX_ARGUMENTS*>(gPostexArgumentsBuffer)->ExitFunc = EXITFUNC_THREAD;
    memcpy(((PPOSTEX_ARGUMENTS)gPostexArgumentsBuffer)->ObfuscateKey, (void*)"AAAA", 4); // Simple key for debugging.
    reinterpret_cast<volatile POSTEX_ARGUMENTS*>(gPostexArgumentsBuffer)->CleanupLoader = 'Y'; // > 0 perform the cleanup, otherwise not
    reinterpret_cast<volatile POSTEX_ARGUMENTS*>(gPostexArgumentsBuffer)->MaxPacketSize = MAX_PACKET_SIZE;
    reinterpret_cast<volatile POSTEX_ARGUMENTS*>(gPostexArgumentsBuffer)->UserArgumentBufferSize = userArgumentBufferSize;

    // Call DllMain in the same fashion as the postex loader.        
    DllEntryPoint(GetModuleHandle(NULL), DLL_PROCESS_ATTACH, NULL, startNamedPipe);
    DllEntryPoint(reinterpret_cast<HMODULE>(placeholderLoaderMemory), DLL_POSTEX_ATTACH, userArgumentBuffer, startNamedPipe);

    return;
}
#endif
