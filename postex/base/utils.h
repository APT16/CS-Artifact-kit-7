#pragma once
#include <cstdio>
#include <vector>

typedef struct _POSTEX_ARGUMENTS {
    DWORD  ExitFunc; 
    char   ObfuscateKey[4]; 
    char   CleanupLoader; 
    int    MaxPacketSize;
    int    UserArgumentBufferSize;
} POSTEX_ARGUMENTS, *PPOSTEX_ARGUMENTS;

typedef struct _USER_ARGUMENT_INFO {
    char* Buffer; 
    int Size;
} USER_ARGUMENT_INFO, *PUSER_ARGUMENT_INFO;

// A structure to hold all user-definable postex data
typedef struct _POSTEX_DATA {
    PPOSTEX_ARGUMENTS PostexArguments;
    USER_ARGUMENT_INFO UserArgumentInfo;
    char* PostexLoaderBaseAddress;
    char* LoadedDllBaseAddress;
    BOOL StartNamedPipe;
} POSTEX_DATA, * PPOSTEX_DATA;

extern volatile char gPostexArgumentsBuffer[sizeof(POSTEX_ARGUMENTS)];

/**
* Swap the endianness of the input variable
*
* @param value The input value
*
* @return A "swapped" value of the same type
*/
template <typename T>
T SwapEndianness(T value) {
    char* ptr = reinterpret_cast<char*>(&value);
    std::reverse(ptr, ptr + sizeof(T));
    return value;
}

/**
* Convert input to bytes
*
* @param value The input value
*
* @return A vector containing the byte representation of the input
*/
template <typename T>
std::vector<char> ToBytes(T input) {
    char* ptr = reinterpret_cast<char*>(&input);
    return std::vector<char>(ptr, ptr + sizeof(T));
}

BOOL CleanupLoaderMemory(char* loaderBaseAddress);
BOOL PostexInit(PPOSTEX_DATA postexData);
void PostexExit(PPOSTEX_DATA postexData);
