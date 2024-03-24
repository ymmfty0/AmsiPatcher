#pragma once
#include <Windows.h>

using _NtProtectVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, PULONG, ULONG, PULONG);


typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesWritten
);

using _WriteProcessMemory = BOOL(WINAPI*)(
	HANDLE  hProcess,
	LPVOID  lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T  nSize,
	SIZE_T* lpNumberOfBytesWritten
);