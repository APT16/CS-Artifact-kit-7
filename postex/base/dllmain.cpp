/*******************************************************************
* Attention: This file should not change. It is the entrypoint to 
* our DLL. Use postexmain.cpp as your postex DLL's main() function.
********************************************************************/
#include "dllmain.h"
#include "macros.h"
#include "utils.h"

// Initialize the postex Data structure
static POSTEX_DATA postexData = { 0 };

BOOL APIENTRY DllEntryPoint(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved, BOOL startNamedPipe) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Save the loaded DLL's image in Release (this can be NULL)
        postexData.LoadedDllBaseAddress = reinterpret_cast<char*>(hModule);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_POSTEX_ATTACH:
        /**
        * Improper synchronization within DllMain can cause an application to deadlock or access data 
        * or code in an uninitialized DLL (LoaderLock).
        * Ref: https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices
        * 
        * As part of postex DLLs, we execute them using our own reflective loader (aka a UDRL).
        * Therefore, we should not be impacted by LoaderLock. In addition, this is the purpose
        * behind this second call to DllMain() with a ul_reason_for_call of DLL_POSTEX_ATTACH.
        * Typically initialization will occur within the default reason codes which means we
        * can avoid interupting those initialization routines by placing the primary logic here.
        */
        postexData.StartNamedPipe = startNamedPipe;
 
        // Save the POSTEX_ARGUMENTS pointer and check its valid
        postexData.PostexArguments = (PPOSTEX_ARGUMENTS)gPostexArgumentsBuffer;
        RETURN_FALSE_ON_NULL(postexData.PostexArguments);

        // Save the static argument buffer size in UserArgumentInfo for clarity
        postexData.UserArgumentInfo.Size = postexData.PostexArguments->UserArgumentBufferSize;
        
        // Check whether static user arguments were sent
        if (postexData.PostexArguments->UserArgumentBufferSize > 0 && lpReserved != NULL) {
            postexData.UserArgumentInfo.Buffer = reinterpret_cast<char*>(lpReserved);
        }
        else {
            /*
            * Here we explicilty set UserArgumentInfo.Buffer to NULL
            * if no arguments are passed. This helps to avoid accidentally 
            * referencing garbage data in situations where the injection 
            * method doesn't support passing arguments to the newly created
            * thread.
            */
            postexData.UserArgumentInfo.Buffer = NULL;
        }

        // Save the loader base address (this can be NULL)
        postexData.PostexLoaderBaseAddress = reinterpret_cast<char*>(hModule);
        
        // Start the pipe server and clean up the loader
        RETURN_FALSE_ON_FALSE(PostexInit(&postexData));

        // Call the postex DLL's main() function		
        PostexMain(&postexData);

        // Close the pipe and exit
        PostexExit(&postexData);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
