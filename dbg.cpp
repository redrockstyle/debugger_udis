#include "dbg.h"
#include "parser.h"
#include <sstream>


void Debugger::InitFlags(PDbgConfig cfg) {
	std::memcpy(&this->config, cfg, sizeof(DbgConfig));
	return;
}
bool Debugger::InitProcess(const unsigned int pid) {
	debugProcess = (HANDLE)pid;
	
	try {
		if (!DebugActiveProcess(pid)) {
			throw std::exception("DebugActiveProcess failed");
		}
		return true;
	}
	catch (const std::exception&) {
		DWORD error = GetLastError();
		if (error == 5) std::cout << "Access denied" << std::endl;
		else if (error == 87) std::cout << "x64 != x32" << std::endl;
		return false;
	}
}
bool Debugger::InitProcess(const std::wstring& path) {

	if (!std::filesystem::exists(path)) {
		std::cout << "File does not exists" << std::endl;
		return false;
	}

	STARTUPINFO startup_info = { 0 };
	PROCESS_INFORMATION process_info = { 0 };

	startup_info.cb = sizeof(startup_info);
	startup_info.dwFlags = STARTF_USESHOWWINDOW;
	startup_info.wShowWindow = SW_SHOWNORMAL;

	if (!CreateProcess(path.c_str(),
		NULL,
		NULL,
		NULL,
		TRUE,
		DEBUG_ONLY_THIS_PROCESS,
		NULL,
		NULL,
		&startup_info,
		&process_info)) {
		std::cout << "CreateProcess did not create process" << std::endl;
		return false;
	}

	debugProcess = process_info.hProcess;
	CloseHandle(process_info.hThread);

	return true;
}

void Debugger::StartDebugging() {
	bool completed = false;
	bool attached = false;

	while (!completed)
	{
		DEBUG_EVENT debugEvent;
		DWORD continueFlag = DBG_CONTINUE;

		if (!WaitForDebugEvent(&debugEvent, INFINITE)) {
			break;
		}

		switch (debugEvent.dwDebugEventCode) {
		case CREATE_PROCESS_DEBUG_EVENT:
			EventCreateProcess(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.CreateProcessInfo);
#if _WIN64
			SetBreakpoint((char*)debugEvent.u.CreateProcessInfo.lpStartAddress, BreakPointType::INITIAL_BREAKPOINT);
#else
			SetBreakpoint((char*)debugEvent.u.CreateProcessInfo.lpStartAddress, BreakPointType::INITIAL_BREAKPOINT);
#endif // _WIN64
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			EventExitProcess(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.ExitProcess);
			completed = true;
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			EventCreateThread(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.CreateThread);
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			EventExitThread(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.ExitThread);
			break;

		case LOAD_DLL_DEBUG_EVENT:
			EventLoadDll(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.LoadDll);
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			EventUnloadDll(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.UnloadDll);
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			EventOutputDebugString(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.DebugString);
			break;

		case EXCEPTION_DEBUG_EVENT:
			if (!attached) {
				// Первое исключение для начала отладки
				attached = true;
			}
			else {
				continueFlag = EventException(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.Exception);
			}
			break;

		default:
			printf("Unexpected debug event: %d\n", debugEvent.dwDebugEventCode);
		}

		if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueFlag)) {
			printf("Error continuing debug event\n");
		}
	}

	CloseHandle(debugProcess);
	return;
}

void Debugger::EventCreateProcess(DWORD pid, DWORD tid, LPCREATE_PROCESS_DEBUG_INFO procDebugInfo) {
	std::cout << "Create process\t\tPID:" << pid;
	std::cout << "\tTID:" << tid << std::endl;
	std::cout << "ImgName:0x" << std::hex << procDebugInfo->lpImageName;
	std::cout << "\tBase:0x" << std::hex << procDebugInfo->lpBaseOfImage;
	std::cout << "\tStart:0x" << procDebugInfo->lpStartAddress << std::endl;

	this->threads.push_back(tid);
	return;
}

void Debugger::EventExitProcess(DWORD pid, DWORD tid, LPEXIT_PROCESS_DEBUG_INFO procDebugInfo) {
	std::cout << "Exit process code:" << procDebugInfo->dwExitCode;
	std::cout << "\tPID:" << std::dec << pid;
	std::cout << "\tTID:" << std::dec << tid << std::endl;
	return;
}

void Debugger::EventCreateThread(DWORD pid, DWORD tid, LPCREATE_THREAD_DEBUG_INFO threadDebugInfo) {
	std::cout << "Thread:" << threadDebugInfo->lpStartAddress;
	std::cout << "\t\tPID:" << std::dec << pid;
	std::cout << "\tTID:" << std::dec << tid << std::endl;

	this->threads.push_back(tid);
	return;
}

void Debugger::EventExitThread(DWORD pid, DWORD tid, LPEXIT_THREAD_DEBUG_INFO threadDebugInfo) {
	std::cout << "Exit thread code:" << threadDebugInfo->dwExitCode;
	std::cout << "\tPID:" << std::dec << pid;
	std::cout << "\tTID:" << std::dec << tid << std::endl;

	auto thr = std::find(this->threads.begin(), this->threads.end(), tid);
	if (this->threads.end() != thr) this->threads.erase(thr);
	return;
}

void Debugger::EventLoadDll(DWORD pid, DWORD tid, LPLOAD_DLL_DEBUG_INFO dllDebugInfo) {
	int i, len;
	char path[MAX_PATH];

	std::cout << "Load dll:" << dllDebugInfo->lpBaseOfDll;
	std::cout << "\tPID:" << std::dec << pid;
	std::cout << "\tTID:" << std::dec << tid;

	//if (dllDebugInfo->lpImageName) {
	//	if (dllDebugInfo->fUnicode) {
	//		std::cout << "W_NAME_ADDR:" << std::hex << dllDebugInfo->lpImageName << std::endl;
	//	}
	//	else {
	//		std::cout << "SZ_NAME_ADDR:" << std::hex << dllDebugInfo->lpImageName << std::endl;
	//	}
	//}

	len = GetFinalPathNameByHandleA(dllDebugInfo->hFile, path, sizeof(path), FILE_NAME_NORMALIZED);
	for (i = len - 1; path[i] != '\\' && i != 0; --i);
	std::cout << " \tName:" << std::string(path + i + 1, path + len) << std::endl;
	this->dll[dllDebugInfo->lpBaseOfDll] = std::string(path + i + 1, path + len);
	return;
}

void Debugger::EventUnloadDll(DWORD pid, DWORD tid, LPUNLOAD_DLL_DEBUG_INFO dllDebugInfo) {
	std::cout << "Unload dll:" << dllDebugInfo->lpBaseOfDll;
	std::cout << "\tPID:" << std::hex << pid;
	std::cout << "\tTID:" << std::hex << tid << std::endl;

	//lib_tracing breakpoints

	this->dll.erase(dllDebugInfo->lpBaseOfDll);
	return;
}

void Debugger::EventOutputDebugString(DWORD pid, DWORD tid, LPOUTPUT_DEBUG_STRING_INFO debugStringInfo) {
	std::string debugString = std::string(debugStringInfo->nDebugStringLength, 0);
	ReadProcessMemory(
		this->debugProcess,
		debugStringInfo->lpDebugStringData,
		&debugString,
		debugStringInfo->nDebugStringLength,
		nullptr
	);

	std::cout << "Debug string:" << debugString;
	std::cout << "\tPID:" << std::hex << pid;
	std::cout << "\tTID:" << std::hex << tid << std::endl;
	return;
}

DWORD Debugger::EventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exceptionDebugInfo) {

	DWORD continueFlag = (DWORD)DBG_EXCEPTION_NOT_HANDLED;
	

	std::string assembly_string;

	switch (exceptionDebugInfo->ExceptionRecord.ExceptionCode)
	{
	case (DWORD)EXCEPTION_BREAKPOINT:
#ifdef _WIN64
	case STATUS_WX86_BREAKPOINT:
#endif
	{
		//std::cout << "EXCEPTION_BREAKPOINT" << std::endl;
		unsigned char* buf;
		char assembly_buffer[128] = { 0 };
		char hex_buffer[128] = { 0 };
		RemoveBreakpoint(exceptionDebugInfo->ExceptionRecord.ExceptionAddress, tid, true);
		buf = new unsigned char[16];
		ReadProcessMemory(this->debugProcess, exceptionDebugInfo->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
		DisasInstruction(buf, 16, (uint64_t)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, assembly_buffer, hex_buffer);
		std::cout << "Instruction: " << assembly_buffer << std::endl;
		std::cout << "Exception Code: " << std::hex << exceptionDebugInfo->ExceptionRecord.ExceptionCode << std::endl;
		delete[] buf;
		
		continueFlag = (DWORD)DBG_CONTINUE;
		break;
	}
	case (DWORD)EXCEPTION_SINGLE_STEP:
#ifdef _WIN64 
	case STATUS_WX86_SINGLE_STEP:
#endif
	{
		//std::cout << "EXCEPTION_SINGLE_STEP" << std::endl;
		CONTEXT ctx = { 0 };
		unsigned char* buf;
		char asmbuf[128] = { 0 };
		char hexbuf[128] = { 0 };
		HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
		if (!thread) {
			break;
		}
		
		if (this->config.baseTracing) {
			SetTraceFlag(thread);

			buf = new unsigned char[16];
			ReadProcessMemory(this->debugProcess, exceptionDebugInfo->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
			DisasInstruction(buf, 16, (uint64_t)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, asmbuf, hexbuf);

			assembly_string = asmbuf;
			std::transform(assembly_string.begin(), assembly_string.end(), assembly_string.begin(), ::toupper);


			if (assembly_string.rfind("CMP", 0) == 0 || assembly_string.rfind("IDIV", 0) == 0) {
				std::cout << "PID: " << std::hex << pid << " TID: " << tid << std::endl;
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);
				debugStream << "INSTRUCTION:" << asmbuf
					<< "\nADDRESS:0x" << std::hex << exceptionDebugInfo->ExceptionRecord.ExceptionAddress
					<< "\nTID:" << std::dec << tid << std::endl;
				PrintRegs(&ctx);
				debugStream << std::endl;
			}
		}
		
		continueFlag = (DWORD)DBG_CONTINUE;
		break;
	}
	default:
	{
		std::cout << "DBG_EXCEPTION_NOT_HANDLED" << std::endl;
		//std::cout << "Unhandled exception @ " << exceptionDebugInfo->ExceptionRecord.ExceptionAddress << std::endl;
		//buf = new char[16];
		//ReadProcessMemory(this->debugProcess, exceptionDebugInfo->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
		//DisasInstruction((unsigned char*)buf, 16, (unsigned int)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, assembly_buffer, hex_buffer);
		//std::cout << "Instruction: " << assembly_buffer << std::endl;
		//std::cout << "Exception Code: " << std::hex << exceptionDebugInfo->ExceptionRecord.ExceptionCode << std::endl;
		//delete[] buf;
		//CloseHandle(thread);
		continueFlag = (DWORD)DBG_EXCEPTION_NOT_HANDLED;
	}
	break;
	}

	return continueFlag;
}

void Debugger::SetBreakpoint(void* addr, BreakPointType type) {
	if (this->breakpoints.find(addr) != this->breakpoints.end()) {
		return;
	}
	unsigned char saveByte = 0;
	ReadProcessMemory(this->debugProcess, (PVOID)addr, &saveByte, 1, nullptr);
	WriteProcessMemory(this->debugProcess, (PVOID)addr, "\xCC", 1, nullptr);
	FlushInstructionCache(this->debugProcess, (PVOID)addr, 1);
	this->breakpoints[addr] = BreakPoint{ saveByte, addr, type};
}

void Debugger::RemoveBreakpoint(void* addr, unsigned int tid, bool ifTrace) {
	HANDLE thread;
	CONTEXT ctx;

	auto found = this->breakpoints.find(addr);
	if (found == this->breakpoints.end() || found->second.type != BreakPointType::INITIAL_BREAKPOINT) {
		return;
	}
	thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
	if (!thread) {
		return;
	}

	std::memset(&ctx, 0, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(thread, &ctx);
	if (ifTrace) ctx.EFlags |= 0x100; //trace flag
	ctx.EIP--;

	SetThreadContext(thread, &ctx);
	WriteProcessMemory(this->debugProcess, addr, &found->second.save, 1, nullptr);
	FlushInstructionCache(this->debugProcess, addr, 1);
	
	this->breakpoints.erase(found);
	CloseHandle(thread);
}

void Debugger::SetTraceFlag(HANDLE& thread) {
	CONTEXT ctx;
	std::memset(&ctx, 0, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(thread, &ctx);
	ctx.EFlags |= 0x100;	// trace flag
	SetThreadContext(thread, &ctx);
}

void Debugger::SetThreadContextToBreakpoint(HANDLE& thread, PVOID& exception_address, unsigned char saveByte, CONTEXT& _ctx) {
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	//_ctx = ctx;
	GetThreadContext(thread, &ctx);
	ctx.EFlags |= 0x100;	//ставим флаг процессора на трассирование
	ctx.EIP--;				//возвращаемся на инструкцию назад, т.е. в EIP будет адрес текущей инструкции

	//this->restored_adress = (DWORD_PTR*)exception_address;
	SetThreadContext(thread, &ctx);
	WriteProcessMemory(this->debugProcess, exception_address, &saveByte, 1, nullptr);
	FlushInstructionCache(this->debugProcess, exception_address, 1);
}

void Debugger::PrintRegs(CONTEXT* ctx) {
#ifdef _WIN64
	_debug_stream << "RAX:" << ctx->Rax << "\tRBX:" << ctx->Rbx <<
		"\tRCX:" << ctx->Rcx << "\tRDX:" << ctx->Rdx <<
		"\tRSI:" << ctx->Rsi << "\tRDI:" << ctx->Rdi <<
		"\nRSP:" << ctx->Rsp << "\tRBP:" << ctx->Rbp <<
		"\tRIP:" << ctx->Rip << "\tR8:" << ctx->R8 <<
		"\tR9:" << ctx->R9 << "\tR10:" << ctx->R10 <<
		"\nR11:" << ctx->R11 << "\tR12:" << ctx->R12 <<
		"\tR13:" << ctx->R13 << "\tR14:" << ctx->R14 <<
		"\tR15:" << ctx->R15 << std::endl;

	std::cout << "RAX:" << ctx->Rax << "\tRBX:" << ctx->Rbx <<
		"\tRCX:" << ctx->Rcx << "\tRDX:" << ctx->Rdx <<
		"\tRSI:" << ctx->Rsi << "\tRDI:" << ctx->Rdi <<
		"\nRSP:" << ctx->Rsp << "\tRBP:" << ctx->Rbp <<
		"\tRIP:" << ctx->Rip << "\tR8:" << ctx->R8 <<
		"\tR9:" << ctx->R9 << "\tR10:" << ctx->R10 <<
		"\nR11:" << ctx->R11 << "\tR12:" << ctx->R12 <<
		"\tR13:" << ctx->R13 << "\tR14:" << ctx->R14 <<
		"\tR15:" << ctx->R15 << std::endl;
#else
	debugStream << "EAX:" << std::hex << ctx->Eax <<
		"\tEBX:" << std::hex << ctx->Ebx <<
		"\tECX:" << std::hex << ctx->Ecx <<
		"\tEDX:" << std::hex << ctx->Edx <<
		"\tESI:" << std::hex << ctx->Esi <<
		"\nEDI:" << std::hex << ctx->Edi <<
		"\tESP:" << std::hex << ctx->Esp <<
		"\tEBP:" << std::hex << ctx->Ebp <<
		"\tEIP:" << std::hex << ctx->Eip << std::endl;

	std::cout << "EAX:" << ctx->Eax <<
		"\tEBX:" << std::hex << ctx->Ebx <<
		"\tECX:" << std::hex << ctx->Ecx <<
		"\tEDX:" << std::hex << ctx->Edx <<
		"\tESI:" << std::hex << ctx->Esi <<
		"\nEDI:" << std::hex << ctx->Edi <<
		"\tESP:" << std::hex << ctx->Esp <<
		"\tEBP:" << std::hex << ctx->Ebp <<
		"\tEIP:" << std::hex << ctx->Eip << std::endl;
#endif
}