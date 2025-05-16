#include <cstdio>
#include <vector>
#include <windows.h>

#include "beacon.h"
#include "dllmain.h"
#include "macros.h"
#include "pipes.h"
#include "utils.h"

/**
* Send formatted output to Beacon.
*
* @param type The callback type
* @param fmt A pointer to the format string
* @param This function can accept a variable number of arguments to support format specifiers.
*/
void BeaconPrintf(int type, const char* fmt, ...) {
    va_list arglist;
    va_start(arglist, fmt);

    // Get the length of the format string
    size_t bufferLength = _vscprintf(fmt, arglist);
    
    // Add space for null terminator '\0'
    bufferLength += 1;
    
    // Create a buffer to hold the formatted string
    char* buffer = new char[bufferLength];
    
    // Create the format string
    int charsWritten = vsprintf_s(buffer, bufferLength, fmt, arglist);
    
    // Send the output
    if (charsWritten > 0) {
        BeaconOutput(type, buffer, charsWritten);
    }
    
    // Cleanup the buffer and the args list
    delete[] buffer;
    va_end(arglist);
    return;
}

/**
* Send raw output to Beacon.
*
* @param type The callback type
* @param data A pointer to the data buffer
* @param length The size of the data buffer
*/
#ifndef _DEBUG
void BeaconOutput(int type, const char* data, int length) {
    /*
    * Split the output into chunks that respects Beacon's
    * max packet size.
    *
    * Chunk Format:
    *
    *  0               1               2               3
    *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    * +-+-+-+-+-+-+-+-+-+-+-+- CHUNK HEADER +-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | Output Length (length of Callback Type and Buffer)            |
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * | Reserved for new flags      |T|        Chunk Id               |
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+ OUTPUT -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * |                        Callback Type                          |
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * |                                                               |
    * |                           Buffer                              |
    * |                                                               |
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    *
    * where the flags are:
    *   - T: Chunk Type (0 = partial, 1 = final)
    */

    // Calculate the max size of the payload
    const int chunkSize = reinterpret_cast<volatile POSTEX_ARGUMENTS*>(gPostexArgumentsBuffer)->MaxPacketSize;
    const int headerSize = 3 * sizeof(DWORD);
    const int maxPayloadSize = chunkSize - headerSize;

    // Allocate the buffer to hold the chunk
    size_t outputBufferLength = headerSize + (maxPayloadSize < length ? maxPayloadSize : length);
    char* output = new char[outputBufferLength];

    unsigned short chunkId = 0;
    int payloadBytesWritten = 0;
    const char* payload = data;

    // Loop over the buffer and write the payload in chunks
    while (payloadBytesWritten < length) {
        int remainingSize = length - payloadBytesWritten;
        int payloadLength = remainingSize < maxPayloadSize ? remainingSize : maxPayloadSize;

        int flags = chunkId |
            ((remainingSize == payloadLength) ? 1 : 0) << 16;

        // Create the chunk
        ((DWORD*)output)[0] = SwapEndianness<int>(sizeof(DWORD) + payloadLength);
        ((DWORD*)output)[1] = SwapEndianness(flags);
        ((DWORD*)output)[2] = SwapEndianness(type);

        // Copy the 'actual' output to the chunk
        memcpy(output + headerSize, payload, payloadLength);

        // Write the chunk
        DWORD numberOfBytesWritten;
        DWORD messageSize = headerSize + payloadLength;
        if (!WriteFile(gPipeHandle, output, messageSize, &numberOfBytesWritten, NULL)) {
            // Free the buffer if the write fails
            delete[] output;
            return;
        }

        // Update the number of bytes written and increment the chunk id
        payloadBytesWritten += payloadLength;
        ++chunkId;
    }
    // Free the buffer
    delete[] output;
    return;
}
#else
// Here we override the BeaconOutput function to print to Console in _DEBUG
void BeaconOutput(int type, const char* data, int length) {
    WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), data, length, NULL, NULL);
    return;
}
#endif

/**
* Initialize a formatp data structure.
* 
* @param format A pointer to the formatp structure
* @param maxSize An integer to define the max size of the structure
*/
void BeaconFormatAlloc(formatp* format, int maxSize) {
    format->original = new char[maxSize];
    format->buffer = format->original;
    format->length = maxSize;
    format->size = maxSize;
    return;
}

/**
* "reset" a formatp data structure.
*
* @param format A pointer to the formatp structure
*/
void BeaconFormatReset(formatp* format) {
    format->buffer = format->original;
    format->length = format->size;
    return;
}

/**
* Free a formatp data structure.
*
* @param format A pointer to the formatp structure
*/
void BeaconFormatFree(formatp* format) {
    delete[] format->original;
    return;
}

/**
* Append data to an existing data buffer.
*
* @param format A pointer to the formatp structure
* @param text A pointer to the data buffer
* @param length The size of the data buffer
*/
void BeaconFormatAppend(formatp* format, char* text, int length) {
    memcpy(format->buffer, text, length);
    format->buffer += length;
    format->length -= length;
    return;
}

/**
* "print" data to the formatp data buffer.
*
* @param format A pointer to the formatp structure
* @param fmt A pointer to a format string
* @param This function can accept a variable number of arguments to support format specifiers.
*/
void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int len = vsprintf_s(format->buffer, format->length, fmt, args);
    format->buffer += len;
    format->length -= len;
    va_end(args);
    return;
}

/**
* Convert a formatp data structure to a character pointer.
*
* @param format A pointer to the formatp structure
* @param size The size of the structure
* 
* @return A char pointer to the string
*/
char* BeaconFormatToString(formatp* format, int* size) {
    if (size)
    {
        *size = format->size - format->length;
    }
    return format->original;
}

/**
* Pack an integer into a formatp structure.
*
* @param format A pointer to the formatp structure
* @param value The input value
*/
void BeaconFormatInt(formatp* format, int value) {
    value = SwapEndianness(value);
    BeaconFormatAppend(format, (char*)&value, 4);
    return;
}

/**
* Parse a given input buffer.
*
* @param parser A pointer to the datap structure
* @param buffer A pointer to the input buffer
* @param size The size of the input buffer
*/
void BeaconDataParse(datap* parser, char* buffer, int size) {
    parser->buffer = buffer;
    parser->original = buffer;
    parser->size = size;
    parser->length = size;
    return;
}

/**
* Retrieve an Integer from a given datap structure.
*
* @param parser A pointer to the datap structure
* 
* @return An Integer 
*/
int BeaconDataInt(datap* parser) {
    int value = *(int*)(parser->buffer);
    parser->buffer += sizeof(int);
    parser->length -= sizeof(int);
    return SwapEndianness(value);
}

/**
* Retrieve a Short from a given datap structure.
*
* @param parser A pointer to the datap structure
*
* @return A Short
*/
short BeaconDataShort(datap* parser) {
    short value = *(short*)(parser->buffer);
    parser->buffer += sizeof(short);
    parser->length -= sizeof(short);
    return SwapEndianness(value);
}

/**
* Retrieve the length of a given datap structure.
*
* @param parser A pointer to the datap structure
*
* @return The size of the data
*/
int BeaconDataLength(datap* parser) {
    return parser->length;
}

/**
* Retrieve a specified buffer from a given datap structure.
*
* @param parser A pointer to the datap structure
* @param size A pointer to an Integer that will receive the size of the required buffer
*
* @return A char pointer to the buffer
*/
char* BeaconDataExtract(datap* parser, int* size) {
    int size_im = BeaconDataInt(parser);
    char* buff = parser->buffer;
    parser->buffer += size_im;
    if (size)
    {
        *size = size_im;
    }
    return buff;
}

/**
* Query the number of bytes in the input buffer.
* 
* @return the number of bytes
*/
DWORD BeaconInputAvailable() {
    return GetAvailableDataFromNamedPipe();
}

/**
* Read a buffer from the named pipe.
* 
* NOTE: This is a blocking call. Use the BeaconInputAvailable
* to first check if the pipe has data.
* 
* @param buffer The pointer to the output buffer
* @param length The number of bytes to read
* @return A Boolean value to indicate success
*/
BOOL BeaconInputRead(char* buffer, DWORD len) {
    return NamedPipeRead(buffer, len);
}
