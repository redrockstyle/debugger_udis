#ifndef _DBG_H_
#define _DBG_H_

#include <Windows.h>

#include <filesystem>
#include <iostream>
#include <vector>
#include <map>

#include "disas.h"

typedef struct _DbgConfig {
	bool baseTracing;
	bool tracing;
	bool functions;
	bool libraries;
}DbgConfig, * PDbgConfig;

typedef enum _BreakPointType {
	TRACING_FUNCTION_BREAKPOINT = 0,
	SAVE_BREAKPOINT,
	INITIAL_BREAKPOINT,
	FUNCTION_RETURN_BREAKPOINT,
	LIB_FUNCTION_BREAKPOINT
} BreakPointType;

typedef struct _BreakPoint {
	unsigned char save;
	void* address;
	BreakPointType type;
	struct _BreakPoint* prev;
} BreakPoint, * PBreakPoint;

class Debugger {
private:
	struct _DbgConfig config;

	HANDLE debugProcess;
	std::vector<DWORD> threads;
	std::map<void*, BreakPoint> breakpoints;
	std::map<void*, std::string> dll;

	void EventCreateProcess(DWORD pid, DWORD tid, LPCREATE_PROCESS_DEBUG_INFO procDebugInfo);
	void EventExitProcess(DWORD pid, DWORD tid, LPEXIT_PROCESS_DEBUG_INFO procDebugInfo);
	void EventCreateThread(DWORD pid, DWORD tid, LPCREATE_THREAD_DEBUG_INFO threadDebugInfo);
	void EventExitThread(DWORD pid, DWORD tid, LPEXIT_THREAD_DEBUG_INFO threadDebugInfo);
	void EventLoadDll(DWORD pid, DWORD tid, LPLOAD_DLL_DEBUG_INFO dllDebugInfo);
	void EventUnloadDll(DWORD pid, DWORD tid, LPUNLOAD_DLL_DEBUG_INFO dllDebugInfo);
	void EventOutputDebugString(DWORD pid, DWORD tid, LPOUTPUT_DEBUG_STRING_INFO debugStringInfo);
	DWORD EventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exceptionDebugInfo);


	//void SetBreakpoint(void* addr, BreakPointType type, BreakPoint* prev);

public:
	Debugger() {
		debugProcess = nullptr;
		config = { 0 };
	};
	void InitFlags(PDbgConfig cfg);
	bool InitProcess(const unsigned int pid);
	bool InitProcess(const std::wstring& path);

	void StartDebugging();

};


#endif // !_DBG_H_
