#ifndef _DBG_H_
#define _DBG_H_

#include <Windows.h>
#ifdef _AMD64_
#define EAX Rax
#define EIP Rip
#define ESP Rsp
#include <ntstatus.h>
#else
#define EAX Eax
#define EIP Eip
#define ESP Esp
#endif

#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>
#include <map>


#include "disas.h"



typedef struct _DbgConfig {
	bool tracing;
	bool functions;
	bool libraries;
}DbgConfig, * PDbgConfig;

enum class BreakPointType {
	TRACING_FUNCTION_BREAKPOINT = 0,
	SAVE_BREAKPOINT,
	INITIAL_BREAKPOINT,
	FUNCTION_RETURN_BREAKPOINT,
	LIB_FUNCTION_BREAKPOINT
};

typedef struct _BreakPoint {
	unsigned char save;
	void* address;
	BreakPointType type;
} BreakPoint, * PBreakPoint;

typedef struct _LibFunctionBreakpoint {
	std::wstring lib_name;
	std::string function_name;
	void* addr;
} LibFunctionBreakpoint, *PLibFunctionBreakpoint;

const std::vector<std::string> tracing_functions_ = {
	"CreateProcessA",
	"CreateProcessAsUserA",
	"ExitProcess",
	"TerminateProcess"
};


const std::map<std::string, std::vector<std::string>> tracing_functions_with_args = {
	{"CreateProcessA", {
		"LPCSTR lpApplicationName", //done
		"LPSTR lpCommandLine", //done
		"LPSECURITY_ATTRIBUTES lpProcessAttributes", //done
		"LPSECURITY_ATTRIBUTES lpThreadAttributes", //done
		"BOOL bInheritHandles", //done
		"DWORD dwCreationFlags", //done
		"LPVOID lpEnvironment",
		"LPCSTR lpCurrentDirectory", //done
		"LPSTARTUPINFOA lpStartupInfo", //done
		"LPPROCESS_INFORMATION lpProcessInformation" //done
}},
	{"CreateProcessW", {
		"LPCWSTR lpApplicationName", //done
		"LPWSTR lpCommandLine", //done
		"LPSECURITY_ATTRIBUTES lpProcessAttributes", //done
		"LPSECURITY_ATTRIBUTES lpThreadAttributes", //done
		"BOOL bInheritHandles", //done
		"DWORD dwCreationFlags", //done
		"LPVOID lpEnvironment",
		"LPCWSTR lpCurrentDirectory", //done
		"LPSTARTUPINFOW lpStartupInfo", //done
		"LPPROCESS_INFORMATION lpProcessInformation" //done
}},
	{"CreateProcessAsUserA", {
		"HANDLE hToken", //done
		"LPCSTR lpApplicationName", //done
		"LPSTR lpCommandLine", //done
		"LPSECURITY_ATTRIBUTES lpProcessAttributes", //done
		"LPSECURITY_ATTRIBUTES lpThreadAttributes", //done
		"BOOL bInheritHandles", //done
		"DWORD dwCreationFlags", //done
		"LPVOID lpEnvironment",
		"LPCSTR lpCurrentDirectory", //done
		"LPSTARTUPINFOA lpStartupInfo", //done
		"LPPROCESS_INFORMATION lpProcessInformation" //done
}},
	{"ExitProcess", {
		"UINT uExitCode", //done
}},
	{"TerminateProcess", {
		"HANDLE hProcess", //done
		"UINT uExitCode", //done
}}
};

class Debugger {
private:
	bool debugging;
	struct _DbgConfig config;
	HANDLE debugProcess;
	std::vector<DWORD> threads;
	std::map<void*, BreakPoint> breakpoints;
	std::map<void*, std::string> dll;
	std::map<void*, std::string> tracing_functions;

	void EventCreateProcess(DWORD pid, DWORD tid, LPCREATE_PROCESS_DEBUG_INFO procDebugInfo);
	void EventExitProcess(DWORD pid, DWORD tid, LPEXIT_PROCESS_DEBUG_INFO procDebugInfo);
	void EventCreateThread(DWORD pid, DWORD tid, LPCREATE_THREAD_DEBUG_INFO threadDebugInfo);
	void EventExitThread(DWORD pid, DWORD tid, LPEXIT_THREAD_DEBUG_INFO threadDebugInfo);
	void EventLoadDll(DWORD pid, DWORD tid, LPLOAD_DLL_DEBUG_INFO dllDebugInfo);
	void EventUnloadDll(DWORD pid, DWORD tid, LPUNLOAD_DLL_DEBUG_INFO dllDebugInfo);
	void EventOutputDebugString(DWORD pid, DWORD tid, LPOUTPUT_DEBUG_STRING_INFO debugStringInfo);
	DWORD EventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exceptionDebugInfo);


	void SetBreakpoint(void* addr, BreakPointType type);
	void RemoveBreakpoint(void* addr);
	void SetTraceFlag(HANDLE& thr, bool decrementEip);
	
	void SetTracingFunctionsBreakpoints(unsigned int tid);

	void PrintRegs(CONTEXT* ctx, bool outConsole);

public:
	std::ofstream debugStream;
	Debugger() {
		debugging = false;
		debugProcess = nullptr;
		config = { 0 };
		debugStream = std::ofstream("debugInfo.txt", std::ios::out);
	};
	void InitFlags(PDbgConfig cfg);
	bool InitProcess(const unsigned int pid);
	bool InitProcess(const std::wstring& path);

	void StartDebugging();

};


#endif // !_DBG_H_
