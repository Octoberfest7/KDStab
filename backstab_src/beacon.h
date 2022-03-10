#pragma once
/*
 * Beacon Object Files (BOF)
 * -------------------------
 * A Beacon Object File is a light-weight post exploitation tool that runs
 * with Beacon's inline-execute command.
 *
 * Cobalt Strike 4.x
 * ChangeLog:
 *    1/25/2022: updated for 4.5
 */

#include <windows.h>
#include <stdio.h>
#include <process.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <tlhelp32.h>
#include <tchar.h>

//MSVCRT
WINBASEAPI void* __cdecl MSVCRT$calloc(size_t _Count, size_t _Size);
WINBASEAPI int __cdecl MSVCRT$_snwprintf(wchar_t* __restrict _Dest, size_t _Count, const wchar_t* __restrict _Format, ...);
WINBASEAPI int __cdecl MSVCRT$atoi(char const* _String);
WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcscpy(wchar_t* __restrict _Dest, const wchar_t* __restrict _Source);
WINBASEAPI wchar_t* __cdecl MSVCRT$wcscmp(const wchar_t* _lhs, const wchar_t* _rhs);
WINBASEAPI long __cdecl MSVCRT$strtol(char const* _String, char** _EndPtr,int _Radix);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t* _Str);
WINBASEAPI void __cdecl MSVCRT$free(void* _Memory);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict _Dst, const void* __restrict _Src, size_t _MaxCount);
WINBASEAPI char* __cdecl MSVCRT$strtok(char* _String, char const* _Delimiter);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char * string1, const char * string2);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);

#define calloc MSVCRT$calloc
#define _snwprintf MSVCRT$_snwprintf
#define atoi MSVCRT$atoi
#define memset MSVCRT$memset
#define wcscpy MSVCRT$wcscpy
#define wcscmp MSVCRT$wcscmp
#define strtol MSVCRT$strtol
#define wcslen MSVCRT$wcslen
#define free MSVCRT$free
#define memcpy MSVCRT$memcpy
#define strtok MSVCRT$strtok
#define _stricmp MSVCRT$_stricmp
#define free MSVCRT$free

//KERNEL32
WINBASEAPI void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
#define HeapAlloc KERNEL32$HeapAlloc
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
#define GetLastError KERNEL32$GetLastError


//ADVAPI32
WINADVAPI BOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI BOOL WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);  //??? ADVAPI32$LookupPrivilegeValueW?
WINADVAPI BOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength); //???
WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
WINADVAPI LONG WINAPI ADVAPI32$RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
WINADVAPI LONG WINAPI ADVAPI32$RegDeleteKeyExW(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved);
WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, CONST BYTE* lpData, DWORD cbData);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);

#define OpenProcessToken ADVAPI32$OpenProcessToken
#define LookupPrivilegeValueW ADVAPI32$LookupPrivilegeValueW
#define AdjustTokenPrivileges ADVAPI32$AdjustTokenPrivileges
#define GetTokenInformation ADVAPI32$GetTokenInformation
#define RegCreateKeyExW ADVAPI32$RegCreateKeyExW
#define RegSetValueExW ADVAPI32$RegSetValueExW 
#define RegDeleteKeyExW ADVAPI32$RegDeleteKeyExW
#define RegCloseKey ADVAPI32$RegCloseKey

/* data API */
typedef struct {
	char* original; /* the original buffer [so we can free it] */
	char* buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char* buffer, int size);
DECLSPEC_IMPORT char* BeaconDataPtr(datap * parser, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap * parser);
DECLSPEC_IMPORT char* BeaconDataExtract(datap * parser, int* size);

/* format API */
typedef struct {
	char* original; /* the original buffer [so we can free it] */
	char* buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, char* text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, char* fmt, ...);
DECLSPEC_IMPORT char* BeaconFormatToString(formatp * format, int* size);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp * format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0d

DECLSPEC_IMPORT void   BeaconOutput(int type, char* data, int len);
DECLSPEC_IMPORT void   BeaconPrintf(int type, char* fmt, ...);


/* Token Functions */
DECLSPEC_IMPORT BOOL   BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void   BeaconRevertToken();
DECLSPEC_IMPORT BOOL   BeaconIsAdmin();

/* Spawn+Inject Functions */
DECLSPEC_IMPORT void   BeaconGetSpawnTo(BOOL x86, char* buffer, int length);
DECLSPEC_IMPORT void   BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len);
DECLSPEC_IMPORT void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION * pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len);
DECLSPEC_IMPORT BOOL   BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, STARTUPINFO * si, PROCESS_INFORMATION * pInfo);
DECLSPEC_IMPORT void   BeaconCleanupProcess(PROCESS_INFORMATION * pInfo);

/* Utility Functions */
DECLSPEC_IMPORT BOOL   toWideChar(char* src, wchar_t* dst, int max);