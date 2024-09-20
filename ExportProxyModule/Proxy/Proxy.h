#pragma once

#include <windows.h>
#include <vector>
#include <cstdarg> // va args
#include "minhook.h"

namespace Proxy
{
	bool DynamicPatchAll();
	bool PatchAllImports(LPCSTR targetDLL);
}

namespace Proxy
{
	std::vector<HMODULE> TargetModules; // target modules
	void* callback = nullptr; // cached callback pointer
	bool bIsInDebug = false; // cached debug enabled state
	bool bHasCheckedDebugCache = false;

	// used for debugging
	void PrintDebugA(const char* Message, ...)
	{
		if (Proxy::bIsInDebug)
		{
			if (!Proxy::bHasCheckedDebugCache) // create console and redirect output to it if in debug mode, making sure to allocate console if no exist
			{
				Proxy::bHasCheckedDebugCache = true;

				if (!GetConsoleWindow())
				{
					AllocConsole();
				}

				FILE* fDummy;
				freopen_s(&fDummy, "CONIN$", "r", stdin);
				freopen_s(&fDummy, "CONOUT$", "w", stderr);
				freopen_s(&fDummy, "CONOUT$", "w", stdout);
			}

			va_list args;
			va_start(args, Message);
			vprintf(Message, args);
			va_end(args);
		}
	}

	// used for debugging
	void PrintDebug(std::string Message)
	{
		

		if (Proxy::bIsInDebug)
		{
			if (!Proxy::bHasCheckedDebugCache) // create console and redirect output to it if in debug mode, making sure to allocate console if no exist
			{
				Proxy::bHasCheckedDebugCache = true;

				if (!GetConsoleWindow())
				{
					AllocConsole();
				}

				FILE* fDummy;
				freopen_s(&fDummy, "CONIN$", "r", stdin);
				freopen_s(&fDummy, "CONOUT$", "w", stderr);
				freopen_s(&fDummy, "CONOUT$", "w", stdout);
			}

			printf(Message.c_str());
		}
	}

	// used for acceptinh farpoc for import patch while not adding shitcode in the usage.
	FARPROC FuncProxy(LPCSTR functionName)
	{
		PrintDebugA("FuncProxy called with function: %s!\r\n", (const char*)functionName);
		if (callback)
		{
			reinterpret_cast<void(*)()>(callback)(); // shitcode af but it works
		}

		return (FARPROC)0;
	}

	// init all stuff
	void init(void* ArgCallback = nullptr, bool bVerboseDebug = false)
	{
		if ((ArgCallback != nullptr) && Proxy::callback == ArgCallback) return; // ignore re-updating.
		if ((!ArgCallback && Proxy::callback) && (Proxy::bIsInDebug == bVerboseDebug)) return; // allow updating debug without specifying callback.
		
		PrintDebugA("updating callback, old: %p, new: %p!\r\n", (void*)Proxy::callback, (void*)ArgCallback);
		Proxy::callback = ArgCallback;
	}

	// patch static imports
	bool PatchAllImports(LPCSTR targetDLL)
	{
		// get the base address of current process
		HMODULE hModule = GetModuleHandleA(NULL); // i absolutely despise wide string users btw yes i mean you dataloden
		if (!hModule)
		{

			PrintDebug("init error, couldn't get base address.\r\n");
			return false;
		}

		// get dos header
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			PrintDebug("init error, base address has invalid magic (not IMAGE_DOS_SIGNATURE).\r\n");
			return false;
		}

		// get nt headers
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
			PrintDebug("init error, base address has invalid nt header magic (not IMAGE_NT_SIGNATURE).\r\n");
			return false;
		}

		// get the import directory
		IMAGE_DATA_DIRECTORY importDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (importDirectory.Size == 0) {
			PrintDebug("init error, no imports found in pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].\r\n");
			return false;
		}

		// locate the import descriptor table
		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importDirectory.VirtualAddress);

		// loop over all static modules imported
		while (pImportDescriptor->Name != NULL) {
			LPCSTR importedDLLName = (LPCSTR)((BYTE*)hModule + pImportDescriptor->Name);
			
			PrintDebugA("found import dll: %s!.\r\n", importedDLLName);

			// check if this is target
			if (_stricmp(importedDLLName, targetDLL) == 0)
			{
				PrintDebugA("found target dll: %s!.\r\n", importedDLLName);

				// get the first thunk (import address table - iat) and original first thunk (import name table)
				PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDescriptor->OriginalFirstThunk);
				PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDescriptor->FirstThunk);

				// loop over static imported func
				while (pOriginalThunk->u1.AddressOfData != NULL) {
					// check if this import is by name (no ordinal)
					if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						++pOriginalThunk;
						++pThunk;
						continue;
					}

					// get the imported func name
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + pOriginalThunk->u1.AddressOfData);
					LPCSTR functionName = (LPCSTR)pImportByName->Name;

					// patch the function by replacing the iat entry with the func addy
					FARPROC newFunction = FuncProxy(functionName);

					// change protection to allow writing to iat
					DWORD oldProtect;
					if (VirtualProtect(&pThunk->u1.Function, sizeof(FARPROC), PAGE_EXECUTE_READWRITE, &oldProtect)) {
						pThunk->u1.Function = (ULONGLONG)newFunction;
						VirtualProtect(&pThunk->u1.Function, sizeof(FARPROC), oldProtect, &oldProtect);
						Proxy::PrintDebugA("successfully patched function: %s!\r\n", functionName);
					}
					else {
						Proxy::PrintDebugA("error: couldn't change protection while patching function: %s!\r\n", functionName);
					}

					++pOriginalThunk;
					++pThunk;
				}
			}


			// move to the next DLL import descriptor
			++pImportDescriptor;
		}

		return (Proxy::DynamicPatchAll() == true);
	}

	// get target modules -> i like this look tbh
	std::vector<HMODULE> GetTargetModules()
	{
		return Proxy::TargetModules; // this is better
	}

	// add to target, optionally use a address instead
	std::vector<HMODULE> AddToTargetModules(std::string TargetName, uintptr_t Target = 0)
	{
		if (Target)
		{
			Proxy::TargetModules.push_back(reinterpret_cast<HMODULE>(Target)); // add to module targets.
		}
		else if (TargetName.c_str())
		{
			HMODULE ModulePointer = GetModuleHandleA(TargetName.c_str());
			if (ModulePointer)
			{
				Proxy::TargetModules.push_back(ModulePointer); // add to module targets.
			}
		}

		// this needs to always be returned so yea idk
		return Proxy::GetTargetModules();
	}

	// add to target (wide string), optionally use a address instead
	std::vector<HMODULE> AddToTargetModulesW(std::wstring TargetName, uintptr_t Target = 0)
	{
		if (Target)
		{
			Proxy::TargetModules.push_back(reinterpret_cast<HMODULE>(Target)); // add to module targets.
		}
		else if (TargetName.c_str())
		{
			HMODULE ModulePointer = GetModuleHandleW(TargetName.c_str());
			if (ModulePointer)
			{
				Proxy::TargetModules.push_back(ModulePointer); // add to module targets.
			}
		}

		// this needs to always be returned so yea idk
		return Proxy::GetTargetModules();
	}

	// check whether in target modules
	bool IsTargetModule(HMODULE ValueToCheck)
	{
		bool bResult = false;

		if (Proxy::GetTargetModules().size() > 0)
		{
			std::vector<HMODULE> mds = Proxy::GetTargetModules(); // easier for me to type tbh

			for (int i = 0; i < mds.size(); i++) // idk if this is good for performance but yeah
			{
				if (mds.at(i) == ValueToCheck)
				{
					bResult = true;
					break;
				}
			}
		}

		return bResult;
	}

	FARPROC(*oGetProcAddress)(HMODULE hModule, LPCSTR lpProcName) = nullptr;
	FARPROC hkGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
	{
		if (hModule == (HMODULE)0xD3ADB33F) // so idiots who use 0xDEADBEEF as a placeholder for this instead of nulltpr dont activate
		{
			PrintDebug("test worked!\r\n");
			return (FARPROC)0; // make sure to not error or something
		}

		if (!oGetProcAddress)
		{
			PrintDebug("WARNING: hkGetProcAddress called without oGetProcAddress!!!! original call with fail!!!!!\r\n");
		}

		bool bIsATargetModule = Proxy::IsTargetModule(hModule);

		PrintDebugA("hkGetProcAddress called with data, module: %p, (bIsATargetModule: %d!), Export name: %s!\r\n", hModule, bIsATargetModule, (const char*)lpProcName);


		if (!bIsATargetModule)
		{
			if (oGetProcAddress)
			{
				void* ReturnAddress = (void*)oGetProcAddress(hModule, lpProcName);
				PrintDebugA("ignoring call, not a target, resulting address: %p!\r\n", ReturnAddress);
			}
			else
			{
				PrintDebug("ignoring call, not a target, no further data due to not being initialized!\r\n");
			}

		}
		else
		{
			if (oGetProcAddress)
			{
				void* ReturnAddress = (void*)oGetProcAddress(hModule, lpProcName);
				PrintDebugA("request is a target module, real return address: %p!\r\n", ReturnAddress);
			}
			else
			{
				PrintDebug("request is a target module, no further data due to not being initialized!\r\n");
			}
			
			if (callback)
			{
				PrintDebugA("returning address: %p!\r\n", (void*)callback);
			}
			else
			{
				PrintDebug("WARNING: request is a target module, but the hook will fail as we haven't initialized!!!!!\r\n");
			}
		}

		if (oGetProcAddress && !bIsATargetModule)
		{
			return oGetProcAddress(hModule, lpProcName);
		}
		else if (bIsATargetModule)
		{
			PrintDebug("returning!\r\n");
			
			if (callback)
			{
				return reinterpret_cast<FARPROC>(callback);
			}
		}

		PrintDebug("WARNING! CATASTROPHIC ERROR!!!!!!!!!\r\n");

		return (FARPROC)0;
	}

	// patches GetProcAddress so we can fix dynamic imports.
	bool DynamicPatchAll()
	{
		MH_STATUS MHInitRes = MH_Initialize();
		if (MHInitRes == MH_STATUS::MH_ERROR_ALREADY_INITIALIZED || MHInitRes == MH_STATUS::MH_OK)
		{
			PrintDebug("successfully init minhook!\r\n");
		}
		else
		{
			PrintDebugA("failed to init minhook, result: %d!\r\n", static_cast<int>(MHInitRes));
			return false;
		}

		void* GetProcAddressPtr = (void*)GetProcAddress; // used for logging and organization tbh
		PrintDebugA("hooking GetProcAddress for dynamic patching (address: %p!)..\r\n", GetProcAddressPtr);
		MH_STATUS DynamicHookCreate = MH_CreateHook((LPVOID)GetProcAddressPtr, (LPVOID)hkGetProcAddress, (LPVOID*)&oGetProcAddress);
		if (DynamicHookCreate != MH_OK)
		{
			PrintDebugA("WARNING: failed to enable dynamic module hook!!!!! result: %d!\r\n", static_cast<int>(DynamicHookCreate));
		}

		MH_STATUS DynamicHookEnable = MH_EnableHook((LPVOID)GetProcAddressPtr);
		if (DynamicHookEnable != MH_OK)
		{
			PrintDebugA("WARNING: failed to enable dynamic module hook!!!!! result: %d!\r\n", static_cast<int>(DynamicHookEnable));
		}

		return true;
	}
}

// easy usage :3
namespace EasyProxy
{
	// init with easy method
	void Init(std::vector<std::string> TargetModules, void* Callback, bool bEnableDebugMode = false)
	{
		if (!Callback) return;

		for (int mod = 0; mod < TargetModules.size(); mod++)
		{
			if (bEnableDebugMode)
				printf("adding target module: %s!\r\n", TargetModules.at(mod).c_str()); // only if debug mode

			Proxy::AddToTargetModules(TargetModules.at(mod).c_str());
		}

		for (int i = 0; i < TargetModules.size(); i++)
		{
			if (Proxy::PatchAllImports(TargetModules.at(i).c_str()))
			{
				if(bEnableDebugMode)
				{
					printf("init hijack for module: %s! :3\r\n", TargetModules.at(i).c_str());
				}
			}
			else 
			{
				if (bEnableDebugMode)
				{
					printf("failed third hijack for module: %s!\r\n", TargetModules.at(i).c_str());
				}
			}
		}

		Proxy::init(Callback, bEnableDebugMode);
	}
}