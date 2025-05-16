#include <windows.h>
#include <cstdio>

#include "beacon.h"
#include "debug.h"
#include "dllmain.h"
#include "macros.h"
#include "mock.h"
#include "pipes.h"
#include "utils.h"

/**
* The postex DLL's main() function
* 
* @param postexData A pointer to a POSTEX_DATA structure
*/
void PostexMain(PPOSTEX_DATA postexData) {
    RETURN_ON_NULL(postexData);
    /**
    * Simple output example
    */ 
    BeaconPrintf(CALLBACK_OUTPUT, "Hello, World!\n");
    BeaconPrintf(CALLBACK_ERROR, "Hello, Error!\n");

    /**
    * Static argument example
    */
    datap dataParser;
    BeaconDataParse(&dataParser, postexData->UserArgumentInfo.Buffer, postexData->UserArgumentInfo.Size);
    if (dataParser.size > 0) {
        int value = BeaconDataInt(&dataParser);
        char* str = BeaconDataExtract(&dataParser, NULL);
        BeaconPrintf(CALLBACK_OUTPUT, "Example int: %d Example argument string: %s!\n", value, str);
    }

    /**
    * Formatted data example
    */ 
    formatp buffer = { 0 };
    BeaconFormatAlloc(&buffer, 1024);
    for (int i = 0; i < 11; i++) {
        // Save output to the buffer 
        BeaconFormatPrintf(&buffer, (char*)"Counter: %i\n", i);
    }

    // Append data to the buffer
    char appendString[] = "Counter: 99\n";
    BeaconFormatAppend(&buffer, (char*)appendString, sizeof(appendString));

    // Send formatted data to console
    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", BeaconFormatToString(&buffer, NULL));

    // Reset the buffer
    BeaconFormatReset(&buffer);

    // Reuse the buffer 
    BeaconFormatPrintf(&buffer, (char*)"Reusing the same buffer\n");

    // Send the formatted data to the console
    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", BeaconFormatToString(&buffer, NULL));

    // Free the buffer
    BeaconFormatFree(&buffer);

    /*
    * Named pipe argument example
    */ 
    int timer = 0;
    DWORD bytesRead = 0;
    while (timer < 15) {
        // Check for data on the pipe
        bytesRead = BeaconInputAvailable();
        // Keep looping until we have something to read.
        if (bytesRead > 0) {
            // Allocate a buffer to hold the data
            char* pipeData = new char[bytesRead + 1]();

            // Add a null byte to the buffer (required for call to BeaconPrintf)
            pipeData[bytesRead] = '\0';

            // Read the pipe and save the output to the buffer
            BeaconInputRead(pipeData, bytesRead);

            // Send the output to the console
            BeaconPrintf(CALLBACK_OUTPUT, "Example pipe data: %s\n", pipeData);

            // Free the bufer
            delete[] pipeData;
        }
        // Increment the timer and sleep before continuing
        timer++;
        Sleep(1000);
    }
    return;
}

#ifdef _DEBUG
/*******************************************************************
* Note: Place any mock postex arguments here when debugging.
********************************************************************/
void main() {
    /*
    * In this example, the pipe server is not started
    * in DEBUG. All output is passed directly to the 
    * console.
    */ 
    BOOL startPipeServer = false;
        
    /**
    * A small example to demonstrate mocking arguments in DEBUG.
    * We pass a pointer to the argument buffer and its size
    * to the DebugEntryPoint function. This information is added to the 
    * USER_ARGUMENT_INFO structure in POSTEX_DATA. This allows 
    * users to work with the familiar BeaconData APIs found in 
    * beacon.h to retrieve arguments etc.
    */
    PostexDataPacker userArguments;
    userArguments.pack<int, const char*>(4444, "foo bar bat");

    // Call the debug entry point
    DebugEntryPoint(userArguments.getData(), userArguments.size(), startPipeServer);
    /**
    * Note: DebugEntryPoint() can also be called without user arguments:
    * DebugEntryPoint(NULL, 0, startPipeServer);
    */
}
#endif

/*******************************************************************
* Attention: Do not remove or modify the code below, it is an
* important part of the template as it abstracts the details of
* DllMain() and the postex argument buffer.
********************************************************************/

/**
* The linker will automatically insert a DLlMain() function if we
* don't define one in our DLL project. To keep postexmain.cpp as 
* simple as possible, we declare DllMain() here and use it to call 
* the "real" DLLMain() in base.lib aka DllEntryPoint()
*
* ref: https://learn.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-2010/2kzt1wy3(v=vs.100)?redirectedfrom=MSDN
*/
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    bool startPipeServer = true; // start the pipe server for the 'Release' build
    return DllEntryPoint(hModule, ul_reason_for_call, lpReserved, startPipeServer);
}

/**
* In order to support malleable C2 profile settings, we need to
* declare this variable here to ensure it is not optimized
* out of the resulting DLL.
*/
volatile char gPostexArgumentsBuffer[20] = "_POSTEX_ARGUMENTS_";