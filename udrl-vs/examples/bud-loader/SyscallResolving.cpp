#include "SyscallResolving.h"
#include "Utils.h"
#include "StdLib.h"
#include "Hash.h"
#include "FunctionResolving.h"

#pragma code_seg(".text$b")

/*
 * IMPORTANT NOTE: This code is intended to demonstrate the Beacon User Data feature and does
 * not provide a comprehensive implementation of resolving system calls. Therefore, the following code
 * serves solely as an illustrative example. Please note that this implementation has certain limitations:
 *
 * 1. The ability to resolve hooked functions is NOT covered in this example
 *
 * 2. This code is NOT designed with operational security (OPSEC) considerations
 */

/**
 * @brief Find the first occurrence of a system call instruction in memory
 *
 * This function searches for a specific system call instruction pattern within the
 * memory block starting at the given address 'addr'. The pattern to search for
 * depends on the target architecture:
 *
 * - On x64, the assembly pattern is: 'syscall; ret;' (0x0f, 0x05, 0xc3)
 * - On x86, the assembly pattern is: 'sysenter; ret;' (0x0f, 0x34, 0xc3)
 *
 * @param addr A pointer to the starting address of the memory block
 * @return A pointer to the first occurrence of the system call instruction pattern
 *         if found, or NULL if the pattern is not found within the first 32 bytes
 */
PBYTE FindSyscallInstruction(PBYTE addr) {
#if _M_X64
    char syscallPattern[] = { '\x0f', '\x05', '\xc3'}; // syscall; ret;
#else
    char syscallPattern[] = { '\x0f', '\x34', '\xc3' }; // sysenter; ret;
#endif
    for (int offset = 0; offset < 32; ++offset) {
        if (!_memcmp(syscallPattern, (char*)addr + offset, sizeof(syscallPattern))) {
            return addr + offset;
        }
    }
    return NULL;
}

/**
 * @brief Find the system call number in the memory block
 *
 * This function searches for a specific pattern within the memory block starting at the
 * given address 'addr' to identify the system call number. The pattern to search for
 * depends on the target architecture:
 *
 * - On x64, the assembly pattern is: 'mov r10, rcx; mov eax, <syscall num>' (0x4c, 0x8b, 0xd1, 0xb8).
 * - On x86, the assembly pattern is: 'mov eax, <syscall num>' (0xb8).
 *
 * @param addr A pointer to the starting address of the memory block.
 * @return The system call number found in memory following the pattern, or 0 if the
 *         pattern is not found within the first 32 bytes.
 *
 */
DWORD FindSyscallNumber(PBYTE addr) {
#if _M_X64
    char syscallPattern[] = { '\x4c', '\x8b', '\xd1', '\xb8'};
#else
    char syscallPattern[] = { '\xb8' };
#endif
    for (int offset = 0; offset < 32; ++offset) {
        if (!_memcmp(syscallPattern, (char*)addr + offset, sizeof(syscallPattern))) {
            DWORD* numAddress = (DWORD*)(addr + offset + sizeof(syscallPattern));
            return *numAddress;
        }
    }
    return 0;
}

/**
 * Resolve a system call number and function address
 *
 * @param entry     A pointer to a SYSCALL_API_ENTRY structure where resolved information
 *                  will be stored.
 * @param funcHash  Hash value representing the target function to resolve.
 * @return A Boolean value to indicate success
 */
BOOL ResolveSyscallEntry(PSYSCALL_API_ENTRY entry, DWORD funcHash) {
    _PPEB pebAddress = GetPEBAddress();

    // Resolve the NT function address
    PVOID fnAddr = (PVOID)GetProcAddressByHash(pebAddress, NTDLLDLL_HASH, funcHash);
    if (!fnAddr) {
        return FALSE;
    }

    // Find the syscall number
    DWORD sysnum = FindSyscallNumber((PBYTE)fnAddr);

    // Find the address of the syscall instruction
    PVOID jmpAddr = FindSyscallInstruction((PBYTE)fnAddr);

#ifdef _M_IX86
    if (!jmpAddr) {
        jmpAddr = (PVOID)__readfsdword(0xc0); // If WoW64, this returns wow64cpu!X86SwitchTo64BitMode
        if (!jmpAddr) { // Real x86 system
            constexpr DWORD hash = CompileTimeHash("KiFastSystemCall");
            jmpAddr = FindSyscallInstruction((PBYTE)GetProcAddressByHash(pebAddress, NTDLLDLL_HASH, hash));
        }
    }
#endif

    // We did not find the syscall
    if (sysnum == 0 || jmpAddr == NULL) {
        return FALSE;
    }

    // Fill the entry
    entry->fnAddr = fnAddr;
    entry->sysnum = sysnum;
    entry->jmpAddr = jmpAddr;

    return TRUE;
}

/**
 * A helper macro for resolving a SYSCALL_API_ENTRY.
 *
 * @param field The field in the SYSCALL_API structure in which the resolved entry will be stored.
 * @param name The function name used to generate a compile-time hash for entry lookup.
 */
#define RESOLVE_ENTRY(field, name) { \
    constexpr DWORD hash = CompileTimeHash(name); \
    if(!ResolveSyscallEntry(&field, hash)) { return FALSE; } \
}

/**
  * Resolve system call function addresses and syscall numbers.
  *
  * @param syscalls A pointer to a SYSCALL_API structure.
  * @return A Boolean value to indicate success
  */
BOOL ResolveSyscalls(PSYSCALL_API syscalls) {
    PRINT("[+] Resolving System Calls...\n");

    RESOLVE_ENTRY(syscalls->ntAllocateVirtualMemory, "NtAllocateVirtualMemory");
    RESOLVE_ENTRY(syscalls->ntAllocateVirtualMemory, "NtAllocateVirtualMemory");
    RESOLVE_ENTRY(syscalls->ntProtectVirtualMemory, "NtProtectVirtualMemory");
    RESOLVE_ENTRY(syscalls->ntFreeVirtualMemory, "NtFreeVirtualMemory");
    RESOLVE_ENTRY(syscalls->ntGetContextThread, "NtGetContextThread");
    RESOLVE_ENTRY(syscalls->ntSetContextThread, "NtSetContextThread");
    RESOLVE_ENTRY(syscalls->ntResumeThread, "NtResumeThread");
    RESOLVE_ENTRY(syscalls->ntCreateThreadEx, "NtCreateThreadEx");
    RESOLVE_ENTRY(syscalls->ntOpenProcess, "NtOpenProcess");
    RESOLVE_ENTRY(syscalls->ntOpenThread, "NtOpenThread");
    RESOLVE_ENTRY(syscalls->ntClose, "NtClose");
    RESOLVE_ENTRY(syscalls->ntCreateSection, "NtCreateSection");
    RESOLVE_ENTRY(syscalls->ntMapViewOfSection, "NtMapViewOfSection");
    RESOLVE_ENTRY(syscalls->ntUnmapViewOfSection, "NtUnmapViewOfSection");
    RESOLVE_ENTRY(syscalls->ntQueryVirtualMemory, "NtQueryVirtualMemory");
    RESOLVE_ENTRY(syscalls->ntDuplicateObject, "NtDuplicateObject");
    RESOLVE_ENTRY(syscalls->ntReadVirtualMemory, "NtReadVirtualMemory");
    RESOLVE_ENTRY(syscalls->ntWriteVirtualMemory, "NtWriteVirtualMemory");
    RESOLVE_ENTRY(syscalls->ntReadFile, "NtReadFile");
    RESOLVE_ENTRY(syscalls->ntWriteFile, "NtWriteFile");
    RESOLVE_ENTRY(syscalls->ntCreateFile, "NtCreateFile");

    PRINT("\t[*] ntAllocateVirtualMemory: %p %p %X\n",
        syscalls->ntAllocateVirtualMemory.fnAddr, syscalls->ntAllocateVirtualMemory.jmpAddr, syscalls->ntAllocateVirtualMemory.sysnum);
    PRINT("\t[*] NtProtectVirtualMemory:  %p %p %X\n",
        syscalls->ntProtectVirtualMemory.fnAddr, syscalls->ntProtectVirtualMemory.jmpAddr, syscalls->ntProtectVirtualMemory.sysnum);
    PRINT("\t[*] ntFreeVirtualMemory:     %p %p %X\n",
        syscalls->ntFreeVirtualMemory.fnAddr, syscalls->ntFreeVirtualMemory.jmpAddr, syscalls->ntFreeVirtualMemory.sysnum);
    PRINT("\t[*] ntGetContextThread:      %p %p %X\n",
        syscalls->ntGetContextThread.fnAddr, syscalls->ntGetContextThread.jmpAddr, syscalls->ntGetContextThread.sysnum);
    PRINT("\t[*] ntSetContextThread:      %p %p %X\n",
        syscalls->ntSetContextThread.fnAddr, syscalls->ntSetContextThread.jmpAddr, syscalls->ntSetContextThread.sysnum);
    PRINT("\t[*] ntResumeThread:          %p %p %X\n",
        syscalls->ntResumeThread.fnAddr, syscalls->ntResumeThread.jmpAddr, syscalls->ntResumeThread.sysnum);
    PRINT("\t[*] ntCreateThreadEx:        %p %p %X\n",
        syscalls->ntCreateThreadEx.fnAddr, syscalls->ntCreateThreadEx.jmpAddr, syscalls->ntCreateThreadEx.sysnum);
    PRINT("\t[*] ntOpenProcess:           %p %p %X\n",
        syscalls->ntOpenProcess.fnAddr, syscalls->ntOpenProcess.jmpAddr, syscalls->ntOpenProcess.sysnum);
    PRINT("\t[*] ntOpenThread:            %p %p %X\n",
        syscalls->ntOpenThread.fnAddr, syscalls->ntOpenThread.jmpAddr, syscalls->ntOpenThread.sysnum);
    PRINT("\t[*] ntClose:                 %p %p %X\n",
        syscalls->ntClose.fnAddr, syscalls->ntClose.jmpAddr, syscalls->ntClose.sysnum);
    PRINT("\t[*] ntCreateSection:         %p %p %X\n",
        syscalls->ntCreateSection.fnAddr, syscalls->ntCreateSection.jmpAddr, syscalls->ntCreateSection.sysnum);
    PRINT("\t[*] ntMapViewOfSection:      %p %p %X\n",
        syscalls->ntMapViewOfSection.fnAddr, syscalls->ntMapViewOfSection.jmpAddr, syscalls->ntMapViewOfSection.sysnum);
    PRINT("\t[*] ntUnmapViewOfSection:    %p %p %X\n",
        syscalls->ntUnmapViewOfSection.fnAddr, syscalls->ntUnmapViewOfSection.jmpAddr, syscalls->ntUnmapViewOfSection.sysnum);
    PRINT("\t[*] ntQueryVirtualMemory:    %p %p %X\n",
        syscalls->ntQueryVirtualMemory.fnAddr, syscalls->ntQueryVirtualMemory.jmpAddr, syscalls->ntQueryVirtualMemory.sysnum);
    PRINT("\t[*] ntDuplicateObject:       %p %p %X\n",
        syscalls->ntDuplicateObject.fnAddr, syscalls->ntDuplicateObject.jmpAddr, syscalls->ntDuplicateObject.sysnum);
    PRINT("\t[*] ntReadVirtualMemory:     %p %p %X\n",
        syscalls->ntReadVirtualMemory.fnAddr, syscalls->ntReadVirtualMemory.jmpAddr, syscalls->ntReadVirtualMemory.sysnum);
    PRINT("\t[*] ntWriteVirtualMemory:    %p %p %X\n",
        syscalls->ntWriteVirtualMemory.fnAddr, syscalls->ntWriteVirtualMemory.jmpAddr, syscalls->ntWriteVirtualMemory.sysnum);
    PRINT("\t[*] ntReadFile:    %p %p %X\n",
        syscalls->ntReadFile.fnAddr, syscalls->ntReadFile.jmpAddr, syscalls->ntReadFile.sysnum);
    PRINT("\t[*] ntWriteFile:    %p %p %X\n",
        syscalls->ntWriteFile.fnAddr, syscalls->ntWriteFile.jmpAddr, syscalls->ntWriteFile.sysnum);
    PRINT("\t[*] ntCreateFile:    %p %p %X\n",
        syscalls->ntCreateFile.fnAddr, syscalls->ntCreateFile.jmpAddr, syscalls->ntCreateFile.sysnum);

    return TRUE;
}

/**
 * Resolve an RTL function address
 *
 * @param address   A pointer to where the resolved information will be stored
 * @param functionHash  Hash value representing the target function to resolve
 * @return A Boolean value to indicate success
 */
BOOL ResolveRtlEntry(PVOID *address, DWORD functionHash) {
    _PPEB pebAddress = GetPEBAddress();

    // Resolve the RTL function address
    PVOID fnAddr = (PVOID)GetProcAddressByHash(pebAddress, NTDLLDLL_HASH, functionHash);
    if (!fnAddr) {
        return FALSE;
    }

    *address = fnAddr;
    return TRUE;
}

/**
 * A helper macro for resolving a RTL function address
 *
 * @param field The field in the RTL_API structure in which the resolved function address will be stored
 * @param name The function name used to generate a compile-time hash for entry lookup
 */
#define RESOLVE_RTL_ENTRY(field, name) { \
    constexpr DWORD hash = CompileTimeHash(name); \
    if(!ResolveRtlEntry(&field, hash)) { return FALSE; } \
}

/**
  * Resolve required RTL functions
  *
  * @param syscalls A pointer to a SYSCALL_API structure
  * @return A Boolean value to indicate success
  */
BOOL ResolveRtlFunctions(PRTL_API rtlFunctions) {
    PRINT("[+] Resolving RTL Functions...\n");

    /* Resolve the RTL function addresses */
    RESOLVE_RTL_ENTRY(rtlFunctions->rtlDosPathNameToNtPathNameUWithStatusAddr, "RtlDosPathNameToNtPathName_U_WithStatus");
    RESOLVE_RTL_ENTRY(rtlFunctions->rtlFreeHeapAddr, "RtlFreeHeap");

    /* The rtlGetProcessHeapAddr is set to the ProcessHeap address from the PEB */
    _PPEB pebAddress = GetPEBAddress();
    if (pebAddress->lpProcessHeap == NULL) {
       return FALSE;
    }
    rtlFunctions->rtlGetProcessHeapAddr = pebAddress->lpProcessHeap;

    PRINT("\t[*] RtlDosPathNameToNtPathName_U_WithStatus:    %p\n", rtlFunctions->rtlDosPathNameToNtPathNameUWithStatusAddr);
    PRINT("\t[*] RtlFreeHeap:    %p\n", rtlFunctions->rtlFreeHeapAddr);
    PRINT("\t[*] rtlGetProcessHeapAddr:    %p\n", rtlFunctions->rtlGetProcessHeapAddr);

    return TRUE;
}