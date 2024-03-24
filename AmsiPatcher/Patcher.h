#pragma once

#include "Internals.h"
#include <Windows.h>
#include <cstdio>
#include <psapi.h>

class Patcher
{
public:
	void OpenSessionPatch();
	void ScanBufferPatch();
private:

	BOOL CreatePowershell(PROCESS_INFORMATION* ppi);
	BOOL FuncPatcher(const BYTE* buf);
	HMODULE GetRemoteModuleHandle(const HANDLE& hProcess, LPCWSTR lpDllName);
	FARPROC GetRemoteProcAddress(HMODULE hRemoteModule, LPCSTR lpProcName);
	BOOL WriteRemoteMemory(HANDLE hProcess , LPVOID addr, const BYTE* buf, size_t size);

};

