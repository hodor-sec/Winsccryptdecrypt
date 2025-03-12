#include <Windows.h>
#include <Psapi.h> 
#include <winternl.h>
#include <Evntprov.h>

#pragma once
// Define NT API function prototypes
// Kernel32 prototypes
typedef BOOL(__stdcall* pCreateProcessA)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );

typedef HANDLE(__stdcall* pOpenProcess)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId
    );

typedef BOOL(__stdcall* pCloseHandle)(
    HANDLE hObject
    );

typedef BOOL(__stdcall* pWriteProcessMemory)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
    );

typedef LPVOID(__stdcall* pVirtualAllocEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
    );

typedef BOOL(__stdcall* pVirtualFreeEx)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD dwFreeType
    );

typedef DWORD(__stdcall* pGetLastError)(
    void
    );

typedef BOOL(__stdcall* pEnumProcesses)(
    DWORD* lpidProcess,
    DWORD cb,
    DWORD* lpcbNeeded
    );

typedef BOOL(__stdcall* pEnumProcessModules)(
    HANDLE hProcess,
    HMODULE* lphModule,
    DWORD cb,
    LPDWORD lpcbNeeded
    );

typedef DWORD(__stdcall* pGetModuleFileNameExA)(
    HANDLE hProcess,
    HMODULE hModule,
    LPSTR lpFilename,
    DWORD nSize
    );

typedef DWORD(__stdcall* pResumeThread)(
    HANDLE hThread
    );

typedef BOOL(__stdcall* pTerminateProcess)(
    HANDLE hProcess,
    UINT uExitCode
    );

typedef HANDLE(__stdcall* pCreateRemoteThread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
    );

typedef DWORD(__stdcall* pWaitForSingleObject)(
    HANDLE hHandle,
    DWORD dwMilliseconds
    );

typedef BOOL(__stdcall* pIsDebuggerPresent)(
    void
    );

typedef BOOL(__stdcall* pFlushInstrucionCache)(
    HANDLE hProcess,
    LPCVOID lpBaseAddress,
    SIZE_T dwSize
    );

// Psapi
typedef BOOL(WINAPI* pEnumProcesses)(
    DWORD* lpidProcess,
    DWORD cb,
    DWORD* lpcbNeeded
    );

typedef BOOL(WINAPI* pEnumProcessModules)(
    HANDLE hProcess,
    HMODULE* lphModule,
    DWORD cb,
    LPDWORD lpcbNeeded
    );

typedef DWORD(WINAPI* pGetModuleFileNameExA)(
    HANDLE hProcess,
    HMODULE hModule,
    LPSTR lpFilename,
    DWORD nSize
    );

// Ntdll
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartAddress,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

// Advapi32
typedef ULONG(WINAPI* pEventWrite)(
    REGHANDLE RegHandle,
    PCEVENT_DESCRIPTOR EventDescriptor,
    ULONG UserDataCount,
    PEVENT_DATA_DESCRIPTOR UserData
    );