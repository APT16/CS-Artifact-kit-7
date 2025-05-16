#pragma once
#include <windows.h>

// Data formatting/parsing structures
typedef struct {
    char*  original; // The original buffer [so we can free it]
    char*  buffer;   // Current pointer into our buffer 
    int    length;   // Remaining length of data 
    int    size;     // Total size of this buffer
} datap;

typedef struct {
    char*  original; // The original buffer [so we can free it]
    char*  buffer;   // Current pointer into our buffer 
    int    length;   // Remaining length of data 
    int    size;     // Total size of this buffer
} formatp;

// Callback types
#define CALLBACK_OUTPUT      0x00
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d
#define CALLBACK_CUSTOM      0x1000
#define CALLBACK_CUSTOM_LAST 0x13ff

#define EXITFUNC_PROCESS 0x56A2B5F0
#define EXITFUNC_THREAD 0x0A2A1DE0
#define MAX_PACKET_SIZE 524288

// Data formatting/parsing APIs
void    BeaconFormatAlloc(formatp* format, int maxsz);
void    BeaconFormatReset(formatp* format);
void    BeaconFormatAppend(formatp* format, char* text, int len);
void    BeaconFormatPrintf(formatp* format, char* fmt, ...);
char*   BeaconFormatToString(formatp* format, int* size);
void    BeaconFormatFree(formatp* format);
void    BeaconFormatInt(formatp* format, int value);

void    BeaconDataParse(datap* parser, char* buffer, int size);
int     BeaconDataInt(datap* parser);
short   BeaconDataShort(datap* parser);
int     BeaconDataLength(datap* parser);
char*   BeaconDataExtract(datap* parser, int* size);

void    BeaconOutput(int type, const char* data, int len);
void    BeaconPrintf(int type, const char* fmt, ...);

// Data input API
DWORD   BeaconInputAvailable();
BOOL    BeaconInputRead(char* buffer, DWORD len);
