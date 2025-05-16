#ifdef _DEBUG
#pragma once
#include <windows.h>

void DebugEntryPoint(char* userArgumentBuffer, int userArgumentBufferSize, BOOL startNamedPipe);
#endif
