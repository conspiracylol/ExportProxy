#include <windows.h>
#include <iostream>

void InputAndExit(int code = 1, bool SkipSleep = false)
{
	if (!SkipSleep)
	{
		Sleep(3000);
	}

	system("pause");
	exit(code);
}

int main()
{
	HMODULE lib = LoadLibraryA("exptest.dll");
	if (!lib)
	{
		printf("LoadLibrary failed with code: 0x%d!\r\n", GetLastError());
		InputAndExit(1);
	}

	const char* exportName = "ThisExportDefinitelyExistsMan";

	//printf("Loaded library, getting export \"%s\"..!\r\n", exportName);

	void* ExportAddress = GetProcAddress(lib, exportName);

	if (!ExportAddress)
	{
		printf("GetProcAddress failed on export: \"%s\", GetProcAddress returned: %p, GetLastError returned: 0x%d!\r\n", exportName, ExportAddress, GetLastError());
		InputAndExit(2);
	}

	printf("Got export, address: %p!\r\n", ExportAddress);

	reinterpret_cast<void(*)()>(ExportAddress)(); // real method.


	printf("done!\r\n");

	InputAndExit(0);
}