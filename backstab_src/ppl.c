// All credits of this code go to @itm4n 
// original source code taken from https://github.com/itm4n/PPLdump

#include "ppl.h"
#include "beacon.h"

BOOL ProcessGetProtectionLevel(DWORD dwProcessId, PDWORD pdwProtectionLevel)
{
	BOOL bReturnValue = FALSE;

	HANDLE hProcess = NULL;
	PROCESS_PROTECTION_LEVEL_INFORMATION level = { 0 };

	if (!(hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId)))
	{
		BeaconPrintf(CALLBACK_ERROR, "OpenProcess");
		goto end;
	}

	if (!GetProcessInformation(hProcess, ProcessProtectionLevelInfo, &level, sizeof(level)))
	{
		BeaconPrintf(CALLBACK_ERROR, "GetProcessInformation");
		goto end;
	}

	*pdwProtectionLevel = level.ProtectionLevel;
	bReturnValue = TRUE;

end:
	if (hProcess)
		CloseHandle(hProcess);

	return bReturnValue;
}

BOOL ProcessGetProtectionLevelAsString(DWORD dwProcessId, LPWSTR* ppwszProtectionLevel)
{
	BOOL bReturnValue = TRUE;

	DWORD dwProtectionLevel = 0;
	LPCWSTR pwszProtectionName = NULL;
	
	if (!ProcessGetProtectionLevel(dwProcessId, &dwProtectionLevel))
		return FALSE;

	*ppwszProtectionLevel = (LPWSTR)LocalAlloc(LPTR, 64 * sizeof(WCHAR));
	if (!*ppwszProtectionLevel)
		return FALSE;

	if( dwProtectionLevel == PROTECTION_LEVEL_WINTCB_LIGHT)
		pwszProtectionName = L"PsProtectedSignerWinTcb-Light";
	else if( dwProtectionLevel == PROTECTION_LEVEL_WINDOWS)
		pwszProtectionName = L"PsProtectedSignerWindows";
	else if( dwProtectionLevel == PROTECTION_LEVEL_WINDOWS_LIGHT)
		pwszProtectionName = L"PsProtectedSignerWindows-Light";
	else if( dwProtectionLevel == PROTECTION_LEVEL_ANTIMALWARE_LIGHT)
		pwszProtectionName = L"PsProtectedSignerAntimalware-Light";
	else if( dwProtectionLevel == PROTECTION_LEVEL_LSA_LIGHT)
		pwszProtectionName = L"PsProtectedSignerLsa-Light";
	else if( dwProtectionLevel == PROTECTION_LEVEL_WINTCB)
		pwszProtectionName = L"PsProtectedSignerWinTcb";
	else if( dwProtectionLevel == PROTECTION_LEVEL_CODEGEN_LIGHT)
		pwszProtectionName = L"PsProtectedSignerCodegen-Light";
	else if( dwProtectionLevel == PROTECTION_LEVEL_AUTHENTICODE)
		pwszProtectionName = L"PsProtectedSignerAuthenticode";
	else if( dwProtectionLevel == PROTECTION_LEVEL_PPL_APP)
		pwszProtectionName = L"PsProtectedSignerPplApp";
	else if( dwProtectionLevel == PROTECTION_LEVEL_NONE)
		pwszProtectionName = L"None";
	else
	{
		pwszProtectionName = L"Unknown";
		bReturnValue = FALSE;
	}
	_snwprintf(*ppwszProtectionLevel, 64, L"%ws", pwszProtectionName);
	
	return bReturnValue;
}
