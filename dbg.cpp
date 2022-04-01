#include "dbg.h"
#include "parser.h"
#include <sstream>


void Debugger::InitFlags(PDbgConfig cfg) {
	std::memcpy(&this->config, cfg, sizeof(DbgConfig));
	std::cout << "FLAGS FUNC:" << this->config.functions
		<< "\tCALL:" << this->config.functionsCall
		<< "\tLIB:" << this->config.libraries
		<< "\tTRACE:" << this->config.tracing
		<< "\tDISAS:" << this->config.disas << std::endl;
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
		//DEBUG_PROCESS | INHERIT_PARENT_AFFINITY,
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
			if (this->config.functions) {
				SetTracingFunctionsBreakpoints(debugEvent.dwThreadId);
			}
			//if (this->config.disas || this->config.tracing || this->config.functionsCall) {
			//	SetTraceFlag(debugEvent.u.CreateProcessInfo.hThread, false);
			//}
			SetBreakpoint((void*)debugEvent.u.CreateProcessInfo.lpStartAddress, BreakPointType::START_POINT, nullptr);
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			EventExitProcess(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.ExitProcess);
			completed = true;
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			EventCreateThread(debugEvent.dwProcessId, debugEvent.dwThreadId, &debugEvent.u.CreateThread);
			//if (this->config.disas || this->config.tracing || this->config.functionsCall) {
			//	SetTraceFlag(debugEvent.u.CreateProcessInfo.hThread, false);
			//}
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

		case OUTPUT_DEBUG_STRING_EVENT: {
			OUTPUT_DEBUG_STRING_INFO& DebugString = debugEvent.u.DebugString;
			WCHAR* msg = new WCHAR[DebugString.nDebugStringLength];

			ReadProcessMemory(debugProcess, DebugString.lpDebugStringData, msg, DebugString.nDebugStringLength, NULL);

			std::cout << "OUTPUT_DEBUG_STRING_EVENT: ";
			if (DebugString.fUnicode) std::wcout << msg << std::endl;
			else std::cout << msg << std::endl;

			delete[]msg;
			break;
		}
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
	std::cout << "Create process\t\tPID:" << std::dec << pid;
	std::cout << "\tTID:" << std::dec << tid << std::endl;
	std::cout << "ImgName:0x" << std::hex << procDebugInfo->lpImageName;
	std::cout << "\tBase:0x" << std::hex << procDebugInfo->lpBaseOfImage;
	std::cout << "\tStart:0x" << procDebugInfo->lpStartAddress << std::endl;

	this->threads.push_back(tid);
	return;
}

void Debugger::EventExitProcess(DWORD pid, DWORD tid, LPEXIT_PROCESS_DEBUG_INFO procDebugInfo) {
	std::cout << "Exit process code:" << std::hex << procDebugInfo->dwExitCode;
	std::cout << "\tPID:" << std::dec << pid;
	std::cout << "\tTID:" << std::dec << tid << std::endl;
	return;
}

void Debugger::EventCreateThread(DWORD pid, DWORD tid, LPCREATE_THREAD_DEBUG_INFO threadDebugInfo) {
	std::cout << "Create thread:" << threadDebugInfo->lpStartAddress;
	std::cout << "\tPID:" << std::dec << pid;
	std::cout << "\tTID:" << std::dec << tid << std::endl;

	this->threads.push_back(tid);
	return;
}

void Debugger::EventExitThread(DWORD pid, DWORD tid, LPEXIT_THREAD_DEBUG_INFO threadDebugInfo) {
	std::cout << "Exit thread code:" << std::hex << threadDebugInfo->dwExitCode;
	std::cout << "\tPID:" << std::dec << pid;
	std::cout << "\tTID:" << std::dec << tid << std::endl;

	auto thr = std::find(this->threads.begin(), this->threads.end(), tid);
	if (this->threads.end() != thr) this->threads.erase(thr);
	return;
}

void Debugger::EventLoadDll(DWORD pid, DWORD tid, LPLOAD_DLL_DEBUG_INFO dllDebugInfo) {
	int i, len;
	char path[MAX_PATH];

	std::cout << "Load dll:0x" << std::hex << dllDebugInfo->lpBaseOfDll;
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
	std::string dll = std::string(path + i + 1, path + len);
	std::cout << " \tName:" << dll
		<< "\tSize: 0x" << std::hex << GetSizeDllInVirtualMemory(dllDebugInfo->lpBaseOfDll) << std::endl;
	this->dll[dllDebugInfo->lpBaseOfDll] = dll;

	return;
}

void Debugger::EventUnloadDll(DWORD pid, DWORD tid, LPUNLOAD_DLL_DEBUG_INFO dllDebugInfo) {
	std::cout << "Unload dll:" << dllDebugInfo->lpBaseOfDll;
	std::cout << "\tPID:" << std::dec << pid;
	std::cout << "\tTID:" << std::dec << tid << std::endl;

	if (this->config.libraries) {
		for (const auto bp : libBreakPoints) {
			if (bp.second.lib_name == this->dll[dllDebugInfo->lpBaseOfDll]) {
				auto b = this->breakpoints[bp.second.addr];
				WriteProcessMemory(this->debugProcess, b.address, &b.save, 1, nullptr);
				FlushInstructionCache(this->debugProcess, b.address, 1);
				this->breakpoints.erase(bp.second.addr);
			}
		}
	}

	this->dll.erase(dllDebugInfo->lpBaseOfDll);
	return;
}

DWORD Debugger::EventException(DWORD pid, DWORD tid, LPEXCEPTION_DEBUG_INFO exceptionDebugInfo) {

	HANDLE thread;
	CONTEXT ctx = {0};
	char asmbuf[128] = { 0 };
	char hexbuf[128] = { 0 };
	std::string asmstr;
	unsigned char*  buf = new unsigned char[16];

	thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
	if (!thread) return DBG_EXCEPTION_NOT_HANDLED;

	switch (exceptionDebugInfo->ExceptionRecord.ExceptionCode)
	{
	case (DWORD)EXCEPTION_BREAKPOINT:
#ifdef _WIN64
	case STATUS_WX86_BREAKPOINT:
#endif
	{
		std::cout << "EXCEPTION_BREAKPOINT " << exceptionDebugInfo->ExceptionRecord.ExceptionAddress << std::endl;
		auto found = this->breakpoints.find(exceptionDebugInfo->ExceptionRecord.ExceptionAddress);
		
		if (found != this->breakpoints.end() && found->second.type == BreakPointType::START_POINT) {
			SetTraceFlag(thread, true);

			WriteProcessMemory(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, &found->second.save, 1, nullptr);
			FlushInstructionCache(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, 1);
			this->breakpoints.erase(found);

			//if (this->config.libraries) {
			//	SetBreakpointsForDll();
			//}
			if (this->config.tracing) {
				SetTraceFlag(thread, false);
			}
		}
		else if (found != this->breakpoints.end() && found->second.type == BreakPointType::CONTINUE_POINT) {
			SetTraceFlag(thread, true);
			std::cout << "CONTINUE" << std::endl;
			WriteProcessMemory(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, &found->second.save, 1, nullptr);
			FlushInstructionCache(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, 1);
			this->breakpoints.erase(found);

			if (this->config.disas) {
				ReadProcessMemory(this->debugProcess, exceptionDebugInfo->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
				DisasInstruction(buf, 16, (size_t)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, asmbuf, hexbuf);
				std::cout << exceptionDebugInfo->ExceptionRecord.ExceptionAddress
					<< "\t" << std::left << std::setw(40) << asmbuf
					<< std::setw(30) << hexbuf
					<< std::setw(10) << before.size
					<< std::setw(10) << before.address << std::endl;
			}
		}
		//else if (found != this->breakpoints.end() && found->second.type == BreakPointType::END_POINT) {
		//	WriteProcessMemory(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, &found->second.save, 1, nullptr);
		//	FlushInstructionCache(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, 1);
		//	this->breakpoints.erase(found);
		//}
		//else if (found != this->breakpoints.end() && found->second.type == BreakPointType::FUNCTION_POINT) {
		//	printf("Exception breakpoint:\tPID: %llu\tTID: %llu\tAddress: %p\tName: %s\n", pid, tid,
		//		exceptionDebugInfo->ExceptionRecord.ExceptionAddress, traceFunctions[exceptionDebugInfo->ExceptionRecord.ExceptionAddress].c_str());

		//	//this->ParseArguments(tid, traceFunctions[exceptionDebugInfo->ExceptionRecord.ExceptionAddress]);

		//	for (auto it = this->threads.begin(); it != this->threads.end(); ++it) {
		//		if ((*it) == tid) continue;
		//		HANDLE thr = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
		//		SuspendThread(thr);
		//		CloseHandle(thr);
		//	}
		//	SetTraceFlag(thread, true);
		//	WriteProcessMemory(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, &found->second.save, 1, nullptr);
		//	FlushInstructionCache(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, 1);

		//	size_t bytesRead = 0;
		//	ReadProcessMemory(this->debugProcess, exceptionDebugInfo->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
		//	bytesRead = DisasInstruction(buf, 16, (unsigned int)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, asmbuf, hexbuf);
		//	SetBreakpoint((void*)((size_t)(exceptionDebugInfo->ExceptionRecord.ExceptionAddress) + bytesRead), BreakPointType::SAVE_POINT, &found->second);
		//}
		else if (found != this->breakpoints.end() && found->second.type == BreakPointType::LIBRARY_POINT) {
			for (auto it = this->threads.begin(); it != this->threads.end(); ++it) {
				if ((*it) != tid) {
					HANDLE thr = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
					SuspendThread(thr);
					CloseHandle(thr);
				}
			}
			std::cout << "\nPID: " << std::dec << pid << "\tTID: " << std::dec << tid
				<< "\t\t" << libBreakPoints[exceptionDebugInfo->ExceptionRecord.ExceptionAddress].lib_name.c_str()
				<< "\nFunction: " << libBreakPoints[exceptionDebugInfo->ExceptionRecord.ExceptionAddress].function_name.c_str()
				<< "\t0x" << exceptionDebugInfo->ExceptionRecord.ExceptionAddress << std::endl;

			SetTraceFlag(thread, true);
			WriteProcessMemory(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, &found->second.save, 1, nullptr);
			FlushInstructionCache(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, 1);

			
			size_t bytesRead = 0;
			ReadProcessMemory(this->debugProcess, exceptionDebugInfo->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
			bytesRead = DisasInstruction((unsigned char*)buf, 16, (unsigned int)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, asmbuf, hexbuf);
			SetBreakpoint((void*)((size_t)(exceptionDebugInfo->ExceptionRecord.ExceptionAddress) + bytesRead), BreakPointType::SAVE_POINT, &found->second);
			
		}
		//else if (found != this->breakpoints.end() && found->second.type == BreakPointType::RETURN_POINT) {
		//	SetTraceFlag(thread, true);
		//	WriteProcessMemory(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, &found->second.save, 1, nullptr);
		//	FlushInstructionCache(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, 1);

		//	size_t functionResult = ctx.EAX;
		//	//PrintFunctionCall(this->funCalls[exceptionDebugInfo->ExceptionRecord.ExceptionAddress].name, this->funCalls[exceptionDebugInfo->ExceptionRecord.ExceptionAddress].arguments, functionResult);
		//}
		else {
			ReadProcessMemory(this->debugProcess, exceptionDebugInfo->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
			DisasInstruction(buf, 16, (uint64_t)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, asmbuf, hexbuf);
			std::cout << "\nUnsupported breakpoint: 0x" << exceptionDebugInfo->ExceptionRecord.ExceptionAddress
				<< "\tPID: " << std::dec << pid
				<< "\tTID: " << std::dec << tid
				<< "\nInstruction: " << asmbuf
				<< "\nException Code: " << std::hex << exceptionDebugInfo->ExceptionRecord.ExceptionCode
				<< " -> " << GetStringExceptoin(exceptionDebugInfo->ExceptionRecord.ExceptionCode) << std::endl;
		}
		break;
	}
	case (DWORD)EXCEPTION_SINGLE_STEP:
#ifdef _WIN64 
	case STATUS_WX86_SINGLE_STEP:
#endif
	{
		//std::cout << "EXCEPTION_SINGLE_STEP " <<  exceptionDebugInfo->ExceptionRecord.ExceptionAddress << std::endl;
		auto found = this->breakpoints.find(exceptionDebugInfo->ExceptionRecord.ExceptionAddress);
		if (this->config.tracing || this->config.functionsCall || this->config.disas) {

			ReadProcessMemory(this->debugProcess, exceptionDebugInfo->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
			
			if (IsNtdllImage(exceptionDebugInfo->ExceptionRecord.ExceptionAddress)) {
				std::cout << "CALL NTDLL\t" << exceptionDebugInfo->ExceptionRecord.ExceptionAddress
					<< "\t" << std::left << std::setw(40) << asmbuf
					<< std::setw(30) << hexbuf << std::setw(10) << before.size << std::endl;
				std::cout << "BEFORE\t" << before.address << "\tAFTER\t" << (size_t)before.address + before.size << std::endl;
				SetBreakpoint((void*)((size_t)before.address + before.size), BreakPointType::CONTINUE_POINT, nullptr);
				break;
			}
			else {
				SetTraceFlag(thread, false);
				before.address = exceptionDebugInfo->ExceptionRecord.ExceptionAddress;
			}
			before.size = DisasInstruction(buf, 16, (size_t)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, asmbuf, hexbuf);
			asmstr = asmbuf;
			std::transform(asmstr.begin(), asmstr.end(), asmstr.begin(), ::toupper);
		}

		if (this->config.tracing) {
			if (asmstr.rfind("DIV", 0) == 0 || asmstr.rfind("IDIV", 0) == 0) {
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);
				debugStream << "INSTRUCTION:" << asmbuf
					<< "\nADDRESS:0x" << std::hex << exceptionDebugInfo->ExceptionRecord.ExceptionAddress
					<< "\nTID:" << std::dec << tid << std::endl;
				std::cout << "INSTRUCTION:" << asmbuf
					<< "\nADDRESS:0x" << std::hex << exceptionDebugInfo->ExceptionRecord.ExceptionAddress
					<< "\nTID:" << std::dec << tid << std::endl;
				PrintRegs(&ctx, true);
				debugStream << std::endl;
				std::cout << std::endl;
			}
		}
		if (this->config.functionsCall){
			if (this->afterRet) {
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);
				std::cout << "RET\tRET_ADDR:" << (size_t)exceptionDebugInfo->ExceptionRecord.ExceptionAddress
					<< "\tRET_VALUE:" << (size_t)ctx.EAX << std::endl;
				this->afterRet = false;
			}

			if (asmstr.rfind("CALL", 0) == 0) {
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);
				//std::cout << "INSTRUCTION:" << asmbuf
				//	<< "\nADDRESS:0x" << std::hex << exceptionDebugInfo->ExceptionRecord.ExceptionAddress
				//	<< "\nTID:" << std::dec << tid << std::endl;
				PrintCallInstruction(ctx, (void*)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, asmstr);
			}
			if (asmstr.rfind("RET", 0) == 0) {
				this->afterRet = true;
				//std::cout << "INSTRUCTION:" << asmbuf
				//	<< "\nADDRESS:0x" << std::hex << exceptionDebugInfo->ExceptionRecord.ExceptionAddress
				//	<< "\nTID:" << std::dec << tid << std::endl;
				ctx.ContextFlags = CONTEXT_ALL;
				GetThreadContext(thread, &ctx);
				PrintRetInstruction(ctx, (void*)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, asmstr);
			}
		}
		if (this->config.disas) {
			std::cout << exceptionDebugInfo->ExceptionRecord.ExceptionAddress
				<< "\t" << std::left << std::setw(40) << asmbuf
				<< std::setw(30) << hexbuf
				<< std::setw(10) << before.size
				<< std::setw(10) << before.address << std::endl;
		}
		//if (found != this->breakpoints.end() && found->second.type == BreakPointType::SAVE_POINT) {
		//	WriteProcessMemory(this->debugProcess, found->second.prev->address, "\xCC", 1, nullptr);
		//	FlushInstructionCache(this->debugProcess, found->second.prev->address, 1);

		//	WriteProcessMemory(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, &found->second.save, 1, nullptr);
		//	FlushInstructionCache(this->debugProcess, (PVOID)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, 1);

		//	this->breakpoints.erase(found);

		//	for (auto it = this->threads.begin(); it != this->threads.end(); ++it) {
		//		HANDLE thr = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
		//		auto val = ResumeThread(thr);
		//		CloseHandle(thr);
		//	}
		//}
		break;
	}
	default:
	{
		ReadProcessMemory(this->debugProcess, exceptionDebugInfo->ExceptionRecord.ExceptionAddress, buf, 16, nullptr);
		DisasInstruction(buf, 16, (uint64_t)exceptionDebugInfo->ExceptionRecord.ExceptionAddress, asmbuf, hexbuf);
		std::cout << "\nBreakpoint address: 0x" << exceptionDebugInfo->ExceptionRecord.ExceptionAddress
			<< "\tPID: " << std::dec << pid
			<< "\tTID: " << std::dec << tid << std::endl;
		std::cout << "Instruction: " << asmbuf << std::endl;
		std::cout << "Exception Code: " << std::hex << exceptionDebugInfo->ExceptionRecord.ExceptionCode
			<< " -> " << GetStringExceptoin(exceptionDebugInfo->ExceptionRecord.ExceptionCode) << std::endl;
		delete[] buf;
		CloseHandle(thread);
		return DBG_EXCEPTION_NOT_HANDLED;
	}
	}
	delete[] buf;
	CloseHandle(thread);
	return DBG_EXCEPTION_HANDLED;
}

void Debugger::SetBreakpoint(void* addr, BreakPointType type, PBreakPoint prev) {
	if (this->breakpoints.find(addr) != this->breakpoints.end()) {
		return;
	}
	unsigned char saveByte = 0;
	ReadProcessMemory(this->debugProcess, (PVOID)addr, &saveByte, 1, nullptr);
	WriteProcessMemory(this->debugProcess, (PVOID)addr, "\xCC", 1, nullptr);
	FlushInstructionCache(this->debugProcess, (PVOID)addr, 1);
	this->breakpoints[addr] = BreakPoint{ saveByte, addr, type, prev};
}

void Debugger::SetTraceFlag(HANDLE& thr, bool decrementEip) {
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(thr, &ctx);
	ctx.EFlags |= 0x100; //trace flag
	if (decrementEip) ctx.EIP--;
	SetThreadContext(thr, &ctx);
}

void Debugger::PrintRegs(CONTEXT* ctx, bool outConsole) {
#ifdef _WIN64
	debugStream << "RAX:" << ctx->Rax << "\tRBX:" << ctx->Rbx <<
		"\tRCX:" << ctx->Rcx << "\tRDX:" << ctx->Rdx <<
		"\tRSI:" << ctx->Rsi << "\tRDI:" << ctx->Rdi <<
		"\nRSP:" << ctx->Rsp << "\tRBP:" << ctx->Rbp <<
		"\tRIP:" << ctx->Rip << "\tR8:" << ctx->R8 <<
		"\tR9:" << ctx->R9 << "\tR10:" << ctx->R10 <<
		"\nR11:" << ctx->R11 << "\tR12:" << ctx->R12 <<
		"\tR13:" << ctx->R13 << "\tR14:" << ctx->R14 <<
		"\tR15:" << ctx->R15 << std::endl;

	if (outConsole) {
		std::cout << "RAX:" << ctx->Rax << "\tRBX:" << ctx->Rbx <<
			"\tRCX:" << ctx->Rcx << "\tRDX:" << ctx->Rdx <<
			"\tRSI:" << ctx->Rsi << "\tRDI:" << ctx->Rdi <<
			"\nRSP:" << ctx->Rsp << "\tRBP:" << ctx->Rbp <<
			"\tRIP:" << ctx->Rip << "\tR8:" << ctx->R8 <<
			"\tR9:" << ctx->R9 << "\tR10:" << ctx->R10 <<
			"\nR11:" << ctx->R11 << "\tR12:" << ctx->R12 <<
			"\tR13:" << ctx->R13 << "\tR14:" << ctx->R14 <<
			"\tR15:" << ctx->R15 << std::endl;
	}
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

	if (outConsole) {
		std::cout << "EAX:" << std::hex << ctx->Eax <<
			"\tEBX:" << std::hex << ctx->Ebx <<
			"\tECX:" << std::hex << ctx->Ecx <<
			"\tEDX:" << std::hex << ctx->Edx <<
			"\tESI:" << std::hex << ctx->Esi <<
			"\nEDI:" << std::hex << ctx->Edi <<
			"\tESP:" << std::hex << ctx->Esp <<
			"\tEBP:" << std::hex << ctx->Ebp <<
			"\tEIP:" << std::hex << ctx->Eip << std::endl;
	}
#endif
}

void Debugger::SetTracingFunctionsBreakpoints(unsigned int tid) {
	for (const auto& [name, _] : funWithArgs) {
		FARPROC address = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), name.c_str());
		SetBreakpoint((void*)(address), BreakPointType::FUNCTION_POINT, nullptr);
		traceFunctions[address] = name;
		std::cout << "Found function " << name << " @ " << address << std::endl;
		std::cout << "Breakpoint set!" << std::endl;
	}
}

void Debugger::SetBreakpointsForDll() {
	std::cout << "Set breakpoint dll:" << std::endl;
	for (const auto dllAddr : this->dll) {
		std::cout << dllAddr.second << std::endl;
		IMAGE_DOS_HEADER doshead;
		ReadProcessMemory(this->debugProcess,
			dllAddr.first,
			&doshead,
			sizeof(IMAGE_DOS_HEADER),
			nullptr);
		if (doshead.e_magic != IMAGE_DOS_SIGNATURE) {
			return;
		}

		IMAGE_NT_HEADERS nthead;
		ReadProcessMemory(this->debugProcess,
			(void*)((size_t)dllAddr.first + doshead.e_lfanew),
			&nthead,
			sizeof(IMAGE_NT_HEADERS),
			nullptr);
		if (nthead.Signature != IMAGE_NT_SIGNATURE || nthead.OptionalHeader.NumberOfRvaAndSizes <= 0) {
			return;
		}

		IMAGE_EXPORT_DIRECTORY expdir;
		ReadProcessMemory(this->debugProcess,
			(void*)((size_t)dllAddr.first + nthead.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
			&expdir,
			sizeof(IMAGE_EXPORT_DIRECTORY),
			nullptr);

		if (expdir.AddressOfNames == 0) {
			return;
		}

		void* base = dllAddr.first;
		WORD* ordbuf = new WORD[expdir.NumberOfNames];
		DWORD* funbuf = new DWORD[expdir.NumberOfFunctions];
		DWORD* namebuf = new DWORD[expdir.NumberOfNames];
		ReadProcessMemory(this->debugProcess, (LPCVOID)((size_t)base + expdir.AddressOfNameOrdinals), ordbuf, expdir.NumberOfNames * sizeof(WORD), nullptr);
		ReadProcessMemory(this->debugProcess, (LPCVOID)((size_t)base + expdir.AddressOfFunctions), funbuf, expdir.NumberOfFunctions * sizeof(DWORD), nullptr);
		ReadProcessMemory(this->debugProcess, (LPCVOID)((size_t)base + expdir.AddressOfNames), namebuf, expdir.NumberOfNames * sizeof(DWORD), nullptr);

		for (DWORD i = 0; i < expdir.NumberOfNames; ++i) {
			char s[128] = { 0 };

			ReadProcessMemory(this->debugProcess, (LPCVOID)((size_t)base + namebuf[i]), s, 128, nullptr);
			auto function_address = (void*)((size_t)base + funbuf[ordbuf[i]]);
			//std::cout << s << " -> " << std::hex << function_address << std::endl;

			SetBreakpoint(function_address, BreakPointType::LIBRARY_POINT, nullptr);
			this->libBreakPoints[function_address] = LibFunBreakpoint{ dllAddr.second, s, function_address };

		}
		delete[] funbuf;
		delete[] ordbuf;
		delete[] namebuf;
	}
};

std::string Debugger::GetStringExceptoin(DWORD except) {

	switch (except)
	{
	case EXCEPTION_ACCESS_VIOLATION:
		return "EXCEPTION_ACCESS_VIOLATION";
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
		return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
	case EXCEPTION_BREAKPOINT:
		return "EXCEPTION_BREAKPOINT";
	case EXCEPTION_DATATYPE_MISALIGNMENT:
		return "EXCEPTION_DATATYPE_MISALIGNMENT";
	case EXCEPTION_FLT_DENORMAL_OPERAND:
		return "EXCEPTION_FLT_DENORMAL_OPERAND";
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:
		return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
	case EXCEPTION_FLT_INEXACT_RESULT:
		return "EXCEPTION_FLT_INEXACT_RESULT";
	case EXCEPTION_FLT_INVALID_OPERATION:
		return "EXCEPTION_FLT_INVALID_OPERATION";
	case EXCEPTION_FLT_OVERFLOW:
		return "EXCEPTION_FLT_OVERFLOW";
	case EXCEPTION_FLT_STACK_CHECK:
		return "EXCEPTION_FLT_STACK_CHECK";
	case EXCEPTION_FLT_UNDERFLOW:
		return "EXCEPTION_FLT_UNDERFLOW";
	case EXCEPTION_ILLEGAL_INSTRUCTION:
		return "EXCEPTION_ILLEGAL_INSTRUCTION";
	case EXCEPTION_IN_PAGE_ERROR:
		return "EXCEPTION_IN_PAGE_ERROR";
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
		return "EXCEPTION_INT_DIVIDE_BY_ZERO";
	case EXCEPTION_INT_OVERFLOW:
		return "EXCEPTION_INT_OVERFLOW";
	case EXCEPTION_INVALID_DISPOSITION:
		return "EXCEPTION_INVALID_DISPOSITION";
	case EXCEPTION_NONCONTINUABLE_EXCEPTION:
		return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
	case EXCEPTION_PRIV_INSTRUCTION:
		return "EXCEPTION_PRIV_INSTRUCTION";
	case EXCEPTION_SINGLE_STEP:
		return "EXCEPTION_SINGLE_STEP";
	case EXCEPTION_STACK_OVERFLOW:
		return "EXCEPTION_STACK_OVERFLOW";
	default:
		return "ONIME";
	}
}

void Debugger::PrintCallInstruction(CONTEXT ctx, void* address, std::string inst) {
	const size_t argcount = 6;
	std::cout << inst.c_str() << "\t" << address << std::endl;

	std::vector<size_t> args;
#ifdef _AMD64_
	for (size_t i = 0; i < argcount; ++i) {
		switch (i) {
		case 0: {
			args.push_back(ctx.Rcx);
			break;
		}
		case 1: {
			args.push_back(ctx.Rdx);
			break;
		}
		case 2: {
			args.push_back(ctx.R8);
			break;
		}
		case 3: {
			args.push_back(ctx.R9);
			break;
		}
		default: {
			size_t value;
			ReadProcessMemory(this->debugProcess, (LPCVOID)(ctx.ESP + (i) * sizeof(size_t)), &value, sizeof(size_t), nullptr);
			args.push_back(value);
		}
		}
	}
#else
	size_t value;
	for (size_t i = 0; i < argcount; ++i) {
		value = 0;
		ReadProcessMemory(this->debugProcess, (LPCVOID)(ctx.ESP + (i) * sizeof(size_t)), &value, sizeof(size_t), nullptr);
		args.push_back(value);
	}
#endif
	for (size_t i = 0; i < args.size(); ++i) {
		std::cout << std::left << std::setw(10) << i << std::setw(20) << args[i] << std::endl;
	}
}

void Debugger::PrintRetInstruction(CONTEXT ctx, void* addr, std::string inst) {
	size_t retaddr;
	ReadProcessMemory(this->debugProcess, (LPCVOID)(ctx.ESP), &retaddr, sizeof(size_t), nullptr);
	std::cout << inst.c_str()
		<< "\tRET_ADDR:" << retaddr
		<< "\tRET_VALUE:"  << std::hex << ctx.EAX
		<< "\tINS_ADDR:" << addr << std::endl;
}


DWORD Debugger::GetSizeDllInVirtualMemory(void* dllAddr) {

	IMAGE_DOS_HEADER doshead;
	ReadProcessMemory(this->debugProcess,
		dllAddr,
		&doshead,
		sizeof(IMAGE_DOS_HEADER),
		nullptr);
	if (doshead.e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}

	IMAGE_NT_HEADERS nthead;
	ReadProcessMemory(this->debugProcess,
		(void*)((size_t)dllAddr + doshead.e_lfanew),
		&nthead,
		sizeof(IMAGE_NT_HEADERS),
		nullptr);
	if (nthead.Signature != IMAGE_NT_SIGNATURE || nthead.OptionalHeader.NumberOfRvaAndSizes <= 0) {
		return NULL;
	}

	return nthead.OptionalHeader.SizeOfImage;
}

bool Debugger::IsNtdllImage(void* address) {

	for (const auto dll : this->dll) {
		//std::cout << "DLL: " << dll.first << " " << dll.second << " \tEIP: " << address << std::endl;
		if ((size_t)dll.first <= (size_t)address && ((size_t)dll.first + GetSizeDllInVirtualMemory(dll.first)) >= (size_t)address) {
			return true;
		}
	}
	return false;
}

//void Debugger::ParseArguments(unsigned int tid, std::string name) {
//	CONTEXT ctx = { 0 };
//	HANDLE thread = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
//	ctx.ContextFlags = CONTEXT_ALL;
//	GetThreadContext(thread, &ctx);
//
//	size_t returnAddress = { 0 };
//	std::vector<size_t> args;
//	ReadProcessMemory(this->debugProcess, (LPCVOID)ctx.ESP, &returnAddress, sizeof(size_t), nullptr);
//
//#ifdef _AMD64_
//	for (size_t i = 0; i < traceFunctions.at(name).size(); ++i) {
//		switch (i) {
//		case 0: {
//			args.push_back(ctx.Rcx);
//			break;
//		}
//		case 1: {
//			args.push_back(ctx.Rdx);
//			break;
//		}
//		case 2: {
//			args.push_back(ctx.R8);
//			break;
//		}
//		case 3: {
//			args.push_back(ctx.R9);
//			break;
//		}
//		default: {
//			size_t value;
//			ReadProcessMemory(this->debugProcess, (LPCVOID)(ctx.ESP + (i + 1) * sizeof(size_t)), &value, sizeof(size_t), nullptr);
//			args.push_back(value);
//		}
//		}
//	}
//#else
//	size_t value;
//	for (size_t i = 0; i < traceFunctions.at(name).size(); ++i) {
//		value = 0;
//		ReadProcessMemory(this->debugProcess, (LPCVOID)(ctx.ESP + (i + 1) * sizeof(size_t)), &value, sizeof(size_t), nullptr);
//		args.push_back(value);
//	}
//#endif
//	this->funCalls[(void*)returnAddress] = FunctionCall{ name, args };
//	SetBreakpoint((void*)returnAddress, BreakPointType::RETURN_POINT, nullptr);
//
//	CloseHandle(thread);
//}

template< typename T >
std::string hexify(T i) {
	std::stringbuf buf;
	std::ostream os(&buf);
	os << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2) << std::hex << i;
	return buf.str().c_str();
}

//void Debugger::PrintFunctionCall(std::string name, std::vector<size_t> arguments, size_t result) {
//	printf("------------------------------------------------------------\n");
//	printf("Function called: %s\n", name.c_str());
//	std::vector<std::string> formattedArguments;
//
//	auto format = [](std::string name, std::string value) {
//		std::stringstream s;
//		s << name << "\tValue: " << value;
//		return s.str();
//	};
//
//	if (name == "HeapCreate") {
//		std::string first = " ";
//		if (arguments[0] & 0x00040000) first += "HEAP_CREATE_ENABLE_EXECUTE ";
//		if (arguments[0] & 0x00000004) first += "HEAP_GENERATE_EXCEPTIONS ";
//		if (arguments[0] & 0x00000001) first += "HEAP_NO_SERIALIZE ";
//		if (first == " ") first = "NONE";
//
//		formattedArguments.push_back(format(traceFunctions.at(name)[0], first));
//		formattedArguments.push_back(format(traceFunctions.at(name)[1], hexify(arguments[1])));
//		formattedArguments.push_back(format(traceFunctions.at(name)[2], hexify(arguments[2])));
//	}
//	else if (name == "HeapDestroy") {
//		formattedArguments.push_back(format(traceFunctions.at(name)[0], hexify(arguments[0])));
//	}
//	else if (name == "HeapAlloc" || name == "HeapFree" || name == "HeapSize") {
//		formattedArguments.push_back(format(traceFunctions.at(name)[0], hexify(arguments[0])));
//
//		std::string second = " ";
//		if (arguments[0] & 0x00000004) second += "HEAP_GENERATE_EXCEPTIONS ";
//		if (arguments[0] & 0x00000001) second += "HEAP_NO_SERIALIZE ";
//		if (arguments[0] & 0x00000008) second += "HEAP_ZERO_MEMORY ";
//		if (second == " ") second = "NONE";
//		formattedArguments.push_back(format(traceFunctions.at(name)[1], second));
//
//		formattedArguments.push_back(format(traceFunctions.at(name)[2], hexify(arguments[2])));
//	}
//	else if (name == "HeapReAlloc") {
//		formattedArguments.push_back(format(traceFunctions.at(name)[0], hexify(arguments[0])));
//
//		std::string second = " ";
//		if (arguments[0] & 0x00000004) second += "HEAP_GENERATE_EXCEPTIONS ";
//		if (arguments[0] & 0x00000001) second += "HEAP_NO_SERIALIZE ";
//		if (arguments[0] & 0x00000010) second += "HEAP_REALLOC_IN_PLACE_ONLY ";
//		if (arguments[0] & 0x00000008) second += "HEAP_ZERO_MEMORY ";
//		if (second == " ") second = "NONE";
//		formattedArguments.push_back(format(traceFunctions.at(name)[1], second));
//
//		formattedArguments.push_back(format(traceFunctions.at(name)[2], hexify(arguments[2])));
//		formattedArguments.push_back(format(traceFunctions.at(name)[3], hexify(arguments[3])));
//	}
//	else if (name == "HeapQueryInformation") {
//		for (size_t i = 0; i < arguments.size(); ++i) {
//			formattedArguments.push_back(format(traceFunctions.at(name)[i], hexify(arguments[i])));
//		}
//	}
//
//	printf("Arguments:\n");
//	for (auto arg : formattedArguments) {
//		printf("  %s\n", arg.c_str());
//	}
//
//	if (name == "HeapQueryInformation") {
//		printf("Side effects:\n");
//		size_t value = 0;
//		ReadProcessMemory(this->debugProcess, (LPCVOID)arguments[2], &value, sizeof(size_t), nullptr);
//		switch (value) {
//		case 0:
//			printf("  HeapInformation: HEAP_STANDARD\n");
//			break;
//		case 1:
//			printf("  HeapInformation: HEAP_LAL\n");
//			break;
//		case 2:
//			printf("  HeapInformation: HEAP_LFH\n");
//			break;
//		}
//
//		if (arguments[4] != NULL) {
//			ReadProcessMemory(this->debugProcess, (LPCVOID)arguments[4], &value, sizeof(size_t), nullptr);
//			printf("  ReturnLength: %X\n", value);
//		}
//	}
//
//	printf("Return value: %X\n", result);
//	printf("------------------------------------------------------------\n");
//}