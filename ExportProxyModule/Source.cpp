#include <windows.h>
#include <iostream>
#include <vector>
#include "./Proxy/Proxy.h"

void ProxiedExport()
{
	printf("export called :3\r\n");
}

BOOL WINAPI DllMain(HMODULE hInst, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		printf("hi from entry point :3\r\n");

		std::vector<std::string> TargetModules = // hijack all exports (dynamic and static) for both of these modules under the current process
		{
			"ExpTest.dll",
			"dwmapi.dll"
		};

		bool DebugMode = false;
		EasyProxy::Init(TargetModules, ProxiedExport, DebugMode); // third argument is debug mode, second is your callback, first is array of target modules.

	}

	return TRUE;
}