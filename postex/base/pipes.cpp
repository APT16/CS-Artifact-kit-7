#include "dllmain.h"
#include "macros.h"
#include "pipes.h"

/*******************************************************************
* Attention: Do not remove or modify the global variables below, they
* are an important part of the template. The pipe name is replaced by the 
* CS client when it creates the postex job.
********************************************************************/
volatile const char gPipeName[] = "\\\\.\\pipe\\POST_EX_PIPE_NAME_PLEASE_DO_NOT_CHANGE_OR_REMOVE";
HANDLE gPipeHandle = INVALID_HANDLE_VALUE;

// Set buffer size to default task size (1Mb) to avoid limitations with the bi-directional communication.
#define BUFFER_SIZE (1024*1024)

/**
* Create the named pipe server and wait for Beacon to connect.
* 
* Note: The below configuration ensures connectivity with Beacon.
* Tread carefully if you change it.
*/
BOOL StartNamedPipeServer() {
    //Create the pipe with the specified name
    gPipeHandle = CreateNamedPipeA(const_cast<LPCSTR>(gPipeName), PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 1, BUFFER_SIZE, BUFFER_SIZE, 0, NULL);
    
    // Check the handle value
    if (gPipeHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Wait for Beacon to connect to the pipe.
    BOOL pipeConnection = FALSE;
    int timer = 0;
    while (!pipeConnection) {
        if (timer == 10) {
            // Timeout, disconnect the pipe and close the handle.
            RETURN_FALSE_ON_FALSE(DisconnectNamedPipe(gPipeHandle));
            RETURN_FALSE_ON_FALSE(CloseHandle(gPipeHandle));
            return FALSE;
        }
        pipeConnection = ConnectNamedPipe(gPipeHandle, NULL);
        // Sleep to make sure the pipe is up. 
        Sleep(1000);
        timer++;
    }	
    return TRUE;
}

/**
* Stop the named pipe server and disconnect the pipe handle.
*/
BOOL StopNamedPipeServer() {
    // Wait for client process to read any data before disconnecting
    RETURN_FALSE_ON_FALSE(FlushFileBuffers(gPipeHandle));
    // Disconnect the pipe
    RETURN_FALSE_ON_FALSE(DisconnectNamedPipe(gPipeHandle));
    // Close the handle
    return CloseHandle(gPipeHandle);
}

/**
* Query the number of bytes in the input buffer.
* 
* @return the number of bytes
*/
DWORD GetAvailableDataFromNamedPipe() {
    DWORD bytesAvailable = 0;
    PeekNamedPipe(gPipeHandle, NULL, 0, NULL, &bytesAvailable, 0);
    return bytesAvailable;
}

/**
* Reads a buffer from the named pipe.
* 
* NOTE: This is a blocking call. It is possible to 
* check if the pipe has data with GetAvailableDataFromNamedPipe().
* 
* @param buffer The pointer to the output buffer
* @param length The number of bytes to read
* @return A Boolean value to indicate success (Use GetLastError the get the extended error info)
*/
BOOL NamedPipeRead(char* buffer, DWORD length) {
    DWORD totalRead = 0;
    while (totalRead < length) {
        DWORD read = 0;
        if (!ReadFile(gPipeHandle, buffer + totalRead, length - totalRead, &read, NULL)) {
            return FALSE;
        }
        totalRead += read;
    }
    return TRUE;
}
