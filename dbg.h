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
#include <optional>
#include <algorithm>
#include <set>
#include <string>
#include <list>
#include <regex>

#include "names.h"


typedef struct _DbgConfig {
	bool tracing;
	bool functions;
	bool functionsCall;
	bool libraries;
	bool disas;
}DbgConfig, * PDbgConfig;

enum class BreakPointType {
	FUNCTION_POINT = 0,
	SAVE_POINT,
	START_POINT,
	CONTINUE_POINT,
	RETURN_POINT,
	LIBRARY_POINT,
	CALL_POINT
};

typedef struct _BeforeInstuction {
	void* address;
	unsigned int size;
} BeforeInstuction, *PBeforeInstuction;

typedef struct _BreakPoint {
	unsigned char save;
	void* address;
	BreakPointType type;
	struct _BreakPoint* prev;
} BreakPoint, * PBreakPoint;

typedef struct _LibFunBreakpoint {
	std::string libName;
	std::string funcName;
	void* addr;
} LibFunBreakpoint, *PLibFunBreakpoint;

typedef struct _FunctionCall {
	std::string name;
	std::vector<size_t> arguments;
} FunctionCall;

class Debugger {
private:
	BeforeInstuction before;
	void* beforeAddress;
	bool afterRet;
	struct _DbgConfig config;
	HANDLE debugProcess;
	std::vector<DWORD> threads;
	std::map<void*, BreakPoint> breakpoints;
	std::map<void*, std::string> dll;
	std::map<void*, std::string> traceFunctions;
	std::map<void*, LibFunBreakpoint> libBreakpoints;
	std::map<void*, FunctionCall> funCalls;

	void EventCreateProcess(DWORD pid, DWORD tid, LPCREATE_PROCESS_DEBUG_INFO procDebugInfo);
	void EventExitProcess(DWORD pid, DWORD tid, LPEXIT_PROCESS_DEBUG_INFO procDebugInfo);
	void EventCreateThread(DWORD pid, DWORD tid, LPCREATE_THREAD_DEBUG_INFO threadDebugInfo);
	void EventExitThread(DWORD pid, DWORD tid, LPEXIT_THREAD_DEBUG_INFO threadDebugInfo);
	void EventLoadDll(DWORD pid, DWORD tid, LPLOAD_DLL_DEBUG_INFO dllDebugInfo);
	void EventUnloadDll(DWORD pid, DWORD tid, LPUNLOAD_DLL_DEBUG_INFO dllDebugInfo);
	DWORD EventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exceptionDebugInfo);


	void SetBreakpoint(void* addr, BreakPointType type, PBreakPoint prev);
	void SetTraceFlag(HANDLE& thr, bool decrementEip);
	void SetBreakPointsForFunctions();

	bool IsNtdllImage(void* address);

	void PrintRegs(CONTEXT* ctx, bool outConsole);
	void PrintInstCall(CONTEXT ctx, void* retAddr, void* address, std::string inst);
	void PrintInstRet(CONTEXT ctx, void* address, std::string inst);
	void ParseArguments(HANDLE& thread, std::string name);
	void PrintFunctionCall(std::string name, std::vector<size_t> arguments, size_t result, TypeParse tp);
	std::string GetStringExceptoin(DWORD except);
	DWORD GetSizeDllInVirtualMemory(void* dllAddr);

public:
	std::ofstream debugStream;
	std::ofstream funcStream;
	Debugger() {
		before = { 0 };
		beforeAddress = nullptr;
		afterRet = false;
		debugProcess = nullptr;
		config = { 0 };
		debugStream = std::ofstream("debugInfo.txt", std::ios::out);
		funcStream = std::ofstream("funcInfo.txt", std::ios::out);
	};
	void InitFlags(PDbgConfig cfg);
	bool InitProcess(const unsigned int pid);
	bool InitProcess(const std::wstring& path);

	void StartDebugging();

};


#endif // !_DBG_H_
