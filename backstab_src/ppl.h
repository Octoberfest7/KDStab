#pragma once
#include "common.h"

typedef struct PROCESS_PROTECTION_LEVEL_INFORMATION {
  DWORD ProtectionLevel;
} PROCESS_PROTECTION_LEVEL_INFORMATION;

BOOL ProcessGetProtectionLevel(DWORD dwProcessId, PDWORD pdwProtectionLevel);
BOOL ProcessGetProtectionLevelAsString(DWORD dwProcessId, LPWSTR* ppwszProtectionLevel);