#include <map>
#include <string>
#include <vector>

enum class TypeParse {
	func = 0,
	sa,
	sia,
	siw,
	pi
};

enum class TypeArgumnet {
	hex = 0,
	boolt,
	dec,
	dw,
	str,
	wstr,
	startProcInfoA,
	startProcInfoW,
	infoProc,
	secAtributes,
	ushort,
	pointer
};

const std::map<std::string, std::pair<std::vector<std::string>, TypeArgumnet>> TypeMatching = {
	{"LPSTARTUPINFOA", {{}, TypeArgumnet::startProcInfoA}},
	{"LPSTARTUPINFOW", {{}, TypeArgumnet::startProcInfoW}},
	{"LPPROCESS_INFORMATION", {{}, TypeArgumnet::infoProc}},
	{"BOOL", {{}, TypeArgumnet::boolt}},
	{"LPSECURITY_ATTRIBUTES", {{}, TypeArgumnet::secAtributes}},
	{"LPCSTR", {{}, TypeArgumnet::str}},
	{"LPSTR", {{}, TypeArgumnet::str}},
	{"LPVOID", {{}, TypeArgumnet::hex}},
	{"DWORD",{{}, TypeArgumnet::dw}},
	{"LPCWSTR", {{}, TypeArgumnet::wstr}},
	{"LPWSTR", {{}, TypeArgumnet::wstr}},
	{"HANDLE", {{}, TypeArgumnet::dec}},
	{"UINT",{{}, TypeArgumnet::dec}},
	{"WORD", {{}, TypeArgumnet::ushort}},
	{"LPBYTE", {{}, TypeArgumnet::pointer}},
};

const std::map<std::string, std::vector<std::string>> funsWithArgs = {
	{"CreateProcessA", {
		"LPCSTR lpApplicationName",
		"LPSTR lpCommandLine",
		"LPSECURITY_ATTRIBUTES lpProcessAttributes",
		"LPSECURITY_ATTRIBUTES lpThreadAttributes",
		"BOOL bInheritHandles",
		"DWORD dwCreationFlags",
		"LPVOID lpEnvironment",
		"LPCSTR lpCurrentDirectory",
		"LPSTARTUPINFOA lpStartupInfo",
		"LPPROCESS_INFORMATION lpProcessInformation"
	}},
	{"CreateProcessW", {
		"LPCWSTR lpApplicationName",
		"LPWSTR lpCommandLine",
		"LPSECURITY_ATTRIBUTES lpProcessAttributes",
		"LPSECURITY_ATTRIBUTES lpThreadAttributes",
		"BOOL bInheritHandles",
		"DWORD dwCreationFlags",
		"LPVOID lpEnvironment",
		"LPCWSTR lpCurrentDirectory",
		"LPSTARTUPINFOW lpStartupInfo",
		"LPPROCESS_INFORMATION lpProcessInformation"
	}},
	{"CreateProcessAsUserA", {
		"HANDLE hToken",
		"LPCSTR lpApplicationName",
		"LPSTR lpCommandLine",
		"LPSECURITY_ATTRIBUTES lpProcessAttributes",
		"LPSECURITY_ATTRIBUTES lpThreadAttributes",
		"BOOL bInheritHandles",
		"DWORD dwCreationFlags",
		"LPVOID lpEnvironment",
		"LPCSTR lpCurrentDirectory",
		"LPSTARTUPINFOA lpStartupInfo",
		"LPPROCESS_INFORMATION lpProcessInformation"
	}},
	{"CreateProcessAsUserW", {
		"HANDLE hToken",
		"LPCWSTR lpApplicationName",
		"LPWSTR lpCommandLine",
		"LPSECURITY_ATTRIBUTES lpProcessAttributes",
		"LPSECURITY_ATTRIBUTES lpThreadAttributes",
		"BOOL bInheritHandles",
		"DWORD dwCreationFlags",
		"LPVOID lpEnvironment",
		"LPCWSTR lpCurrentDirectory",
		"LPSTARTUPINFOW lpStartupInfo",
		"LPPROCESS_INFORMATION lpProcessInformation"
	}},
	{"ExitProcess", {
		"UINT uExitCode",
	}},
	{"TerminateProcess", {
		"HANDLE hProcess",
		"UINT uExitCode",
	}}
};

const std::map<std::string, std::vector<std::string>> argSecAtr = {
	{"LPSECURITY_ATTRIBUTES", {
		"DWORD nLength",
		"LPVOID lpSecurityDescriptor",
		"BOOL bInheritHandle"}}
};
const std::map<std::string, std::vector<std::string>> argSIa = {
	{"LPSTARTUPINFOA", {
		"DWORD cb",
		"LPSTR lpReserved",
		"LPSTR lpDesktop",
		"LPSTR lpTitle",
		"DWORD dwX",
		"DWORD dwY",
		"DWORD dwXSize",
		"DWORD dwYSize",
		"DWORD dwXCountChars",
		"DWORD dwYCountChars",
		"DWORD dwFillAttribute",
		"DWORD dwFlags",
		"WORD wShowWindow",
		"WORD cbReserved2",
		"LPBYTE lpReserved2",
		"HANDLE hStdInput",
		"HANDLE hStdOutput",
		"HANDLE hStdError"}}
};
const std::map<std::string, std::vector<std::string>> argSIw = {
	{"LPSTARTUPINFOW", {
		"DWORD cb",
		"LPWSTR lpReserved",
		"LPWSTR lpDesktop",
		"LPWSTR lpTitle",
		"DWORD dwX",
		"DWORD dwY",
		"DWORD dwXSize",
		"DWORD dwYSize",
		"DWORD dwXCountChars",
		"DWORD dwYCountChars",
		"DWORD dwFillAttribute",
		"DWORD dwFlags",
		"WORD wShowWindow",
		"WORD cbReserved2",
		"LPBYTE lpReserved2",
		"HANDLE hStdInput",
		"HANDLE hStdOutput",
		"HANDLE hStdError"}}
};
const std::map<std::string, std::vector<std::string>> argPI = {
	{"LPPROCESS_INFORMATION", {
		"HANDLE hProcess",
		"HANDLE hThread",
		"DWORD dwProcessId",
		"DWORD dwThreadId"
	}}
};