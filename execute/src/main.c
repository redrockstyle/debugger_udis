// **********************************
// test debugging
// functions
// CreateProcessA/CreateProcessW, CreateProcessAsUserA/CreateProcessAsUserW, ExitProcess, TerminateProcess
// **********************************
#include <Windows.h>
#define SHOW_CONSOLE	FALSE
#define DO_PROC_EXIT	TRUE
#define DO_MY_EXIT		FALSE
#define EXIT_CODE		0x100
#define FILENAME_A		"callfun.exe"
#define FILENAME_W		L"callfun.exe"


WCHAR buffer[0x100];

void CallCreateProcessA(HWND hWnd);
void CallCreateProcessW(HWND hWnd);
void CallProcessAsUserA(HWND hWnd);
void CallProcessAsUserW(HWND hWnd);
void CallTerminateProcess(HWND hWnd, HANDLE handle, UINT exitCode);


int main() {

	HANDLE handle = GetCurrentProcess();
	DWORD pid = GetCurrentProcessId();
	DWORD tid = GetCurrentThreadId();
	HWND hWnd = GetForegroundWindow();
	if (SHOW_CONSOLE) ShowWindow(hWnd, SW_HIDE);

	wsprintf(buffer, L"PID:%d TID:%d", pid, tid);
	MessageBoxW(hWnd, buffer, L"ProcessID", MB_OK);


	CallCreateProcessA(hWnd);
	CallCreateProcessW(hWnd);	
	CallProcessAsUserA(hWnd);
	CallProcessAsUserW(hWnd);
	//ret = TerminateProcess();

	if (DO_MY_EXIT) ExitProcess(EXIT_CODE);

	return 0;
}

void CallCreateProcessA(HWND hWnd) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD ret = 0;

	memset(&si, 0, sizeof(STARTUPINFO));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));

	ret = CreateProcessA(FILENAME_A,
		NULL,
		NULL,
		NULL,
		TRUE,
		DEBUG_ONLY_THIS_PROCESS,
		//DEBUG_PROCESS | INHERIT_PARENT_AFFINITY,
		NULL,
		NULL,
		(LPSTARTUPINFOA) & si,
		(LPPROCESS_INFORMATION) & pi);

	if (!ret) {
		wsprintf(buffer, L"Error create process\nCode: %d", GetLastError());
		MessageBoxW(hWnd, buffer, L"CreateProcessA", MB_OK);
	}
	else {
		wsprintf(buffer, L"PID:%d TID:%d", pi.dwProcessId, pi.dwThreadId);
		MessageBoxW(hWnd, buffer, L"CreateProcessA", MB_OK);
	}

	if (DO_PROC_EXIT) {
		CallTerminateProcess(hWnd, pi.hProcess, 0);
	}
	else {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}

void CallCreateProcessW(HWND hWnd) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	DWORD ret = 0;

	memset(&si, 0, sizeof(STARTUPINFO));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));

	ret = CreateProcessW(FILENAME_W,
		NULL,
		NULL,
		NULL,
		TRUE,
		DEBUG_PROCESS,
		//DEBUG_PROCESS | INHERIT_PARENT_AFFINITY,
		NULL,
		NULL,
		&si,
		&pi);

	if (!ret) {
		wsprintf(buffer, L"Error create process\nCode: %d", GetLastError());
		MessageBoxW(hWnd, buffer, L"CreateProcessW", MB_OK);
	}
	else {
		wsprintf(buffer, L"PID:%d TID:%d", pi.dwProcessId, pi.dwThreadId);
		MessageBoxW(hWnd, buffer, L"CreateProcessW", MB_OK);
	}

	if (DO_PROC_EXIT) {
		CallTerminateProcess(hWnd, pi.hProcess, 0);
	}
	else {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}

void CallProcessAsUserA(HWND hWnd) {
	HANDLE hUserToken;
	DWORD ret;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ret = LogonUserW(L"User",
		L"FLEX-PC",
		L"findet",
		LOGON32_LOGON_INTERACTIVE,
		LOGON32_PROVIDER_DEFAULT,
		&hUserToken);

	if (!ret)  {
		wsprintf(buffer, L"Error LogonUser\nCode: %d", GetLastError());
		MessageBoxW(hWnd, buffer, L"LogonUser", MB_OK);
		return;
	}
	ret = ImpersonateLoggedOnUser(hUserToken);

	if (!ret) {
		wsprintf(buffer, L"Error ImpersonateLoggedOnUser\nCode: %d", GetLastError());
		MessageBoxW(hWnd, buffer, L"ImpersonateLoggedOnUser", MB_OK);
		CloseHandle(hUserToken);
		return;
	}

	memset(&si, 0, sizeof(STARTUPINFO));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	ret = CreateProcessAsUserA(hUserToken,
		FILENAME_A,
		FILENAME_A,
		NULL,
		NULL,
		TRUE,
		DEBUG_ONLY_THIS_PROCESS,
		NULL,
		NULL,
		(LPSTARTUPINFOA) &si,
		(LPPROCESS_INFORMATION) & pi);


	if (!ret) {
		wsprintf(buffer, L"Error CreateProcessAsUserA\nCode: %d", GetLastError());
		MessageBoxW(hWnd, buffer, L"CreateProcessAsUserA", MB_OK);
		RevertToSelf();
		CloseHandle(hUserToken);
		return;
	}
	else {
		wsprintf(buffer, L"PID:%d TID:%d", pi.dwProcessId, pi.dwThreadId);
		MessageBoxW(hWnd, buffer, L"CreateProcessAsUserA", MB_OK);
	}

	RevertToSelf();
	CloseHandle(hUserToken);

	if (DO_PROC_EXIT) {
		CallTerminateProcess(hWnd, pi.hProcess, 0);
	}
	else {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}

void CallProcessAsUserW(HWND hWnd) {
	HANDLE hUserToken;
	DWORD ret;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ret = LogonUserW(L"User",
		L"FLEX-PC",
		L"findet",
		LOGON32_LOGON_INTERACTIVE,
		LOGON32_PROVIDER_DEFAULT,
		&hUserToken);

	if (!ret) {
		wsprintf(buffer, L"Error LogonUser\nCode: %d", GetLastError());
		MessageBoxW(hWnd, buffer, L"LogonUser", MB_OK);
		return;
	}
	ret = ImpersonateLoggedOnUser(hUserToken);

	if (!ret) {
		wsprintf(buffer, L"Error ImpersonateLoggedOnUser\nCode: %d", GetLastError());
		MessageBoxW(hWnd, buffer, L"ImpersonateLoggedOnUser", MB_OK);
		CloseHandle(hUserToken);
		return;
	}

	memset(&si, 0, sizeof(STARTUPINFO));
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	si.cb = sizeof(STARTUPINFO);

	ret = CreateProcessAsUserW(hUserToken,
		FILENAME_W,
		FILENAME_W,
		NULL,
		NULL,
		TRUE,
		DEBUG_ONLY_THIS_PROCESS,
		NULL,
		NULL,
		(LPSTARTUPINFOW)&si,
		(LPPROCESS_INFORMATION)&pi);


	if (!ret) {
		wsprintf(buffer, L"Error CreateProcessAsUserW\nCode: %d", GetLastError());
		MessageBoxW(hWnd, buffer, L"CreateProcessAsUserW", MB_OK);
		RevertToSelf();
		CloseHandle(hUserToken);
		return;
	}
	else {
		wsprintf(buffer, L"PID:%d TID:%d", pi.dwProcessId, pi.dwThreadId);
		MessageBoxW(hWnd, buffer, L"CreateProcessAsUserW", MB_OK);
	}

	RevertToSelf();
	CloseHandle(hUserToken);

	if (DO_PROC_EXIT) {
		CallTerminateProcess(hWnd, pi.hProcess, 0);
	}
	else {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}

void CallTerminateProcess(HWND hWnd, HANDLE process, UINT exitCode) {
	BOOL ret = TerminateProcess(process, exitCode);

	if (!ret) {
		wsprintf(buffer, L"Error TerminateProcess\nCode: %d", GetLastError());
		MessageBoxW(hWnd, buffer, L"TerminateProcess", MB_OK);
	}
	else {
		wsprintf(buffer, L"Process exit with code %d", exitCode);
		MessageBoxW(hWnd, buffer, L"TerminateProcess", MB_OK);
	}
}