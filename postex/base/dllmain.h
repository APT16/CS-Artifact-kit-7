#pragma once
#include <windows.h>

#include "utils.h"

#define DLL_POSTEX_ATTACH 0x4

extern USER_ARGUMENT_INFO gUserArguments;

BOOL APIENTRY DllEntryPoint(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved, BOOL startNamedPipe);
void PostexMain(PPOSTEX_DATA postexData);
