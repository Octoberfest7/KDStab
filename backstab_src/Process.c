#include "Processes.h"
#include "ProcExp.h"
#include <tlhelp32.h>
#include <tchar.h>

PSYSTEM_HANDLE_INFORMATION ReAllocateHandleInfoTableSize(ULONG ulTable_size, PSYSTEM_HANDLE_INFORMATION handleInformationTable) {

	HANDLE hHeap = GetProcessHeap();
	BOOL ret = HeapFree(hHeap, HEAP_NO_SERIALIZE, handleInformationTable); //first call handleInformationTable will be NULL, which is OK according to the documentation

	handleInformationTable = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ulTable_size);
	CloseHandle(hHeap);
	return handleInformationTable;
}


PSYSTEM_HANDLE_INFORMATION GetHandleInformationTable() {

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInformationTable = NULL;

	ULONG ulSystemInfoLength = sizeof(SYSTEM_HANDLE_INFORMATION) + (sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO) * 100) - 2300;

	//getting the address of NtQuerySystemInformation procedure, using the predefined type fNtQuerySystemInformation

		fNtQuerySystemInformation _NtQuerySystemInformation;
		_NtQuerySystemInformation =
		(fNtQuerySystemInformation)GetLibraryProcAddress("ntdll", "NtQuerySystemInformation");

	handleInformationTable = ReAllocateHandleInfoTableSize(ulSystemInfoLength, handleInformationTable);
	while ((status = _NtQuerySystemInformation(
		CONST_SYSTEM_HANDLE_INFORMATION,
		handleInformationTable,
		ulSystemInfoLength,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		handleInformationTable = ReAllocateHandleInfoTableSize(ulSystemInfoLength *= 2, handleInformationTable);
	}


	if (!NT_SUCCESS(status))
		BeaconPrintf(CALLBACK_ERROR, "ReAllocateHandleInfoTableSize: %d", GetLastError());


	return handleInformationTable;
}



VOID ListProcessHandles(HANDLE hProcess, HANDLE hProcExpDevice) {

	DWORD		PID = GetProcessId(hProcess);
	ULONG		returnLenght = 0;
	SYSTEM_HANDLE_ENTRY handleInfo = { 0 };
	PSYSTEM_HANDLE_INFORMATION handleTableInformation = NULL;

	handleTableInformation = GetHandleInformationTable();
	BeaconPrintf(CALLBACK_OUTPUT, "\nHandle  Type   Device\n=======================\n");



	for (ULONG i = 0; i < handleTableInformation->Count; i++)
	{
		handleInfo = handleTableInformation->Handle[i];

		if (handleInfo.OwnerPid == PID) //meaning that the handle is within our process of interest
		{
			PrintProtectedHandleInformation(PID, handleInfo.HandleValue, handleInfo.ObjectPointer, hProcExpDevice);
		}
	}
	BeaconPrintf(CALLBACK_OUTPUT, "\n");
	HANDLE hHeap = GetProcessHeap();
	BOOL ret = HeapFree(hHeap, HEAP_NO_SERIALIZE, handleTableInformation);
	CloseHandle(hHeap);
}


PVOID GetObjectAddressFromHandle(DWORD dwPID, USHORT usTargetHandle)
{
	ULONG ulReturnLenght = 0;

	PSYSTEM_HANDLE_INFORMATION handleTableInformation = GetHandleInformationTable();

	for (ULONG i = 0; i < handleTableInformation->Count; i++)
	{
		SYSTEM_HANDLE_ENTRY handleInfo = handleTableInformation->Handle[i];

		if (handleInfo.OwnerPid == dwPID) //meaning that the handle is within our process of interest
		{
			if (handleInfo.HandleValue == usTargetHandle)
			{
				HANDLE hHeap = GetProcessHeap();
				BOOL ret = HeapFree(hHeap, HEAP_NO_SERIALIZE, handleTableInformation);
				CloseHandle(hHeap);
				return handleInfo.ObjectPointer;
			}
		}
	}
	HANDLE hHeap = GetProcessHeap();
	BOOL ret = HeapFree(hHeap, HEAP_NO_SERIALIZE, handleTableInformation);
	CloseHandle(hHeap);
	return NULL;
}

BOOL GetProcessPIDFromName(LPSTR szProcessName, PDWORD lpPID) {
	HANDLE			hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL			bRet = FALSE;
	DWORD			dwMatchCount = 0;
	PROCESSENTRY32	pe32;


	if (hSnapshot == INVALID_HANDLE_VALUE)
		return Error("CreateToolhelp32Snapshot");

	pe32.dwSize = sizeof(PROCESSENTRY32);

	bRet = Process32First(hSnapshot, &pe32);
	if (!bRet)
		return Error("GetProcessNameFromPID.Process32First");


	do {
		if (_stricmp(szProcessName, pe32.szExeFile) == 0)
		{
			dwMatchCount++;
			*lpPID = pe32.th32ProcessID;
		}
	} while (Process32Next(hSnapshot, &pe32));


	if (dwMatchCount > 1)
	{
		*lpPID = 1;
		return FALSE;
	}

	if (dwMatchCount == 0)
	{
		*lpPID = 2;
		return FALSE;
	}

	CloseHandle(hSnapshot);
	return TRUE;
}

VOID KillProcessHandles(HANDLE hProcess, HANDLE hProcExpDevice) {

	DWORD dwPID = GetProcessId(hProcess);
	ULONG ulReturnLenght = 0;

	//allocating memory for the SYSTEM_HANDLE_INFORMATION structure in the heap

	PSYSTEM_HANDLE_INFORMATION handleTableInformation = GetHandleInformationTable();

	for (ULONG i = 0; i < handleTableInformation->Count; i++)
	{
		SYSTEM_HANDLE_ENTRY handleInfo = handleTableInformation->Handle[i];

		if (handleInfo.OwnerPid == dwPID) //meaning that the handle is within our process of interest
		{
			/* Check if the process is already killed every 15 closed handles (otherwise we'll keep trying to close handles that are already closed) */
			if (i % 15 == 0)
			{
				DWORD dwProcStatus = 0;
				GetExitCodeProcess(hProcess, &dwProcStatus);
				if (dwProcStatus != STILL_ACTIVE)
				{
					return;
				}
			}
			ProcExpKillHandle(dwPID, handleInfo.HandleValue, hProcExpDevice);
		}
	}
	HANDLE hHeap = GetProcessHeap();
	BOOL ret = HeapFree(hHeap, HEAP_NO_SERIALIZE, handleTableInformation);
	CloseHandle(hHeap);
}