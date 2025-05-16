#pragma once
#include "Windows.h"
#include "BeaconUserData.h"

BOOL ResolveSyscalls(PSYSCALL_API syscalls);
BOOL ResolveRtlFunctions(PRTL_API rtls);
