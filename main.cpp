#include <iostream>
#include <string>
#include <Windows.h>
#include "dbg.h"

bool isNumb(const std::wstring& s) {
	auto it = s.begin();
	while (it != s.end() && std::isdigit(*it))
		++it;
	return !s.empty() && it == s.end();
}

int main() {
	LPWSTR* sArgs;
	int nArgs, i;
	DbgConfig configDbg;
	Debugger dbg;

	sArgs = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	std::memset(&configDbg, 0, sizeof(DbgConfig));

	if (!sArgs) {
		throw new std::exception("CommandLineToArgvW failed");
		return 1;
	}
	else {
		for (i = 1; i < nArgs; i++) {
			if (sArgs[i]) {
				if (wcscmp(sArgs[i], L"-t") == 0) { // base tracing
					configDbg.tracing = 1;
				}
				else if (wcscmp(sArgs[i], L"-b") == 0) {
					configDbg.baseTracing = 1;
				}
				else if (wcscmp(sArgs[i], L"-f") == 0) { // func tracing
					configDbg.functions = 1;
				}
				else if (wcscmp(sArgs[i], L"-l") == 0) { // lib tracing
					configDbg.libraries = 1;
				}
				else if (wcscmp(sArgs[i], L"-i") == 0) { // select target
					if (sArgs[i + 1]) {
						++i;
						if (isNumb(sArgs[i])) {
							if (!dbg.InitProcess(std::stoi(sArgs[i]))) {
								std::cout << "Error init process pid" << std::endl;
								return 2;
							}
						}
						else {
							if (!dbg.InitProcess(sArgs[i])) {
								std::cout << "Error init process path" << std::endl;
								return 3;
							}
						}
					}
				}
			}
		}
	}
	dbg.InitFlags(&configDbg);
	dbg.StartDebugging();


	return 0;
}