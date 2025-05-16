#pragma once
#include <windows.h>

extern HANDLE gPipeHandle;
extern volatile const char gPipeName[];

BOOL StartNamedPipeServer();
BOOL StopNamedPipeServer();
DWORD GetAvailableDataFromNamedPipe();
BOOL NamedPipeRead(char* buffer, DWORD length);
