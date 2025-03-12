#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <conio.h> 
#include <io.h>
#include <Windows.h>

// Link to Windows system libraries
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ws2_32.lib")

// Static variables
#define AES_KEY_SIZE 32  // 256 bits for AES-256
#define AES_BLOCK_SIZE 16
#define LINE_WIDTH 80
#define B64_MAX_LEN 1024
#define MAX_RETRIES 25
#define XOR_KEY_SIZE 16

/* Fancy colors */
#define COLOR_BOLD_BLUE     "\033[1;34m"
#define COLOR_BOLD_RED      "\033[1;31m"
#define COLOR_BOLD_WHITE    "\033[1;37m"
#define COLOR_BOLD_GREEN    "\033[1;32m"
#define COLOR_BOLD_YELLOW   "\033[1;93m"
#define COLOR_OFF           "\033[m"

/* Output encrypted and decrypted */
static void print_data(const char* title, const void* data, int len, int is_oneliner, unsigned char* badChars, int badCharsLen, int line_width);
/* Read contents of a file as argument */
char* readFile(const char* filename, int* fileSize);
/* Check if any bad character is in the encrypted data */
int contains_bad_characters(const unsigned char* data, int len, unsigned char* badChars, int badCharsLen);
/* Secure password input for Windows */
unsigned char* secure_getpass(const char* prompt);
/* Pretty print base64 */
void pretty_print_base64(const char* b64str);
/* Enable ASCII coloring for badchars */
static void enableAnsiEscapeSequences();
/* XOR function */
char* xor_with_key(const unsigned char* data, size_t len);
/* Base64 function */
char* base64_encode(const unsigned char* input, size_t length);
/* Generate printable XOR key */
void gen_xor_key(unsigned char* xorKey);
/* Global XOR key */
unsigned char xorKey[XOR_KEY_SIZE];

int main(int argc, char** argv)
{
    // Variables
    int lenBits = AES_KEY_SIZE * 8;  // AES-256 (256 bits)
    char* shell_in;     // Entered input
    int lenShell;       // Length of shellcode
    unsigned char* badChars = NULL;
    int badCharsLen = 0;
    unsigned char salt[16];
    unsigned char ivEnc[16];

    // Check args
    if (argc < 2) {
        printf("Usage: %s <shellcode_as_file> [-b \"<bad_characters>\"]\n", argv[0]);
        printf("Enter shellcode as filename argument and password as regular input.\n\n");
        exit(-1);
    }

    // Generate random XOR key
    gen_xor_key(xorKey);

    // Enable colored output for badchars
    enableAnsiEscapeSequences();

    // Process -b argument for bad characters
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            // Parse bad characters from the argument
            size_t len = strlen(argv[i + 1]);
            badCharsLen = len / 4;  // Each bad byte is specified as \xNN (4 chars)
            badChars = malloc(badCharsLen);
            for (int j = 0; j < badCharsLen; j++) {
                sscanf_s(argv[i + 1] + j * 4 + 2, "%2hhx", &badChars[j]);  // Skipping "\x"
            }
            break;
        }
    }

    // Read shellcode from file
    if (!(shell_in = readFile(argv[1], &lenShell))) {
        printf("[!] Unable to read given file, does it exist?\n\n");
        exit(-1);
    }

    // Password input using secure_getpass (Windows alternative to getpass)
    unsigned char* key = secure_getpass("Enter password to encrypt: ");
    int lenKey = strlen((char*)key);

    // Buffers for encryption
    const size_t lenEnc = ((lenShell + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;  // Ensure we have a multiple of AES_BLOCK_SIZE
    unsigned char* shell_enc = malloc(lenEnc);
    if (!shell_enc) {
        perror("[!] malloc failed");
        exit(-1);
    }
    memset(shell_enc, 0, lenEnc);  // Padding the encrypted data buffer

    // Initialize the EVP context for encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[!] Error creating EVP context\n");
        exit(-1);
    }

    // Encryption loop with retry logic to avoid bad characters
    int attempt = 0;
    int containsBadChars = 1;
    while (attempt < MAX_RETRIES && containsBadChars) {
        // Recalculate salt and IV on each attempt
        if (!RAND_bytes(salt, sizeof(salt))) {
            fprintf(stderr, "[!] Error generating random salt\n");
            exit(-1);
        }

        // Generate a random IV
        if (!RAND_bytes(ivEnc, sizeof(ivEnc))) {
            fprintf(stderr, "[!] Error generating random IV\n");
            exit(-1);
        }

        unsigned char derivedKey[AES_KEY_SIZE + AES_BLOCK_SIZE];  // Key and IV (256-bit key + 128-bit IV)
        if (!PKCS5_PBKDF2_HMAC_SHA1((char*)key, lenKey, salt, sizeof(salt), 10000, sizeof(derivedKey), derivedKey)) {
            fprintf(stderr, "[!] Error deriving key and IV with PBKDF2\n");
            exit(-1);
        }

        unsigned char* aesKey = derivedKey;
        unsigned char* ivEnc = derivedKey + AES_KEY_SIZE;

        // Initialize AES-256-CBC encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, ivEnc) != 1) {
            fprintf(stderr, "[!] Error initializing encryption\n");
            EVP_CIPHER_CTX_free(ctx);
            exit(-1);
        }

        // Encrypt the shellcode with padding
        int outLen = 0;
        if (EVP_EncryptUpdate(ctx, shell_enc, &outLen, (unsigned char*)shell_in, lenShell) != 1) {
            fprintf(stderr, "[!] Error during encryption\n");
            EVP_CIPHER_CTX_free(ctx);
            exit(-1);
        }

        // Ensure padding is added
        int finalLen = 0;
        if (EVP_EncryptFinal_ex(ctx, shell_enc + outLen, &finalLen) != 1) {
            fprintf(stderr, "[!] Error finalizing encryption\n");
            EVP_CIPHER_CTX_free(ctx);
            exit(-1);
        }

        containsBadChars = contains_bad_characters(shell_enc, lenEnc, badChars, badCharsLen);
        if (containsBadChars) {
            attempt++;
            printf("\n");
            printf("[*] Bad characters found! Re-encrypting... (Attempt %d/%d)\n", attempt, MAX_RETRIES);
            print_data(COLOR_BOLD_WHITE "\nRE-ENCRYPTED" COLOR_OFF, shell_enc, lenEnc, 0, badChars, badCharsLen, LINE_WIDTH);
        }
    }

    if (containsBadChars) {
        printf("[!] Failed to eliminate bad characters after %d attempts. Exiting.\n", MAX_RETRIES);
        EVP_CIPHER_CTX_free(ctx);
        exit(-1);
    }

    // Output encrypted data and IV
    print_data(COLOR_BOLD_YELLOW "\nORIGINAL" COLOR_OFF, shell_in, lenShell, 0, badChars, badCharsLen, LINE_WIDTH);
    print_data(COLOR_BOLD_GREEN "\nENCRYPTED" COLOR_OFF, shell_enc, lenEnc, 0, badChars, badCharsLen, LINE_WIDTH);

    // Print success after encryption rounds
    printf("\n[+] Encrypted shellcode without bad characters after %d attempt(s) of encryption.\n", attempt+=1);

    // XOR and Base64 variables
    char* b64xorKey = base64_encode(xorKey, sizeof(xorKey));
    char* xorshell_enc = xor_with_key(shell_enc, lenEnc);
    char* b64shell_enc = base64_encode(xorshell_enc,lenEnc);
    char* xorivEnc = xor_with_key(ivEnc, sizeof(ivEnc));
    char* b64ivEnc = base64_encode(xorivEnc, sizeof(ivEnc));
    char* xorsalt = xor_with_key(salt, sizeof(salt));
    char* b64salt = base64_encode(xorsalt, sizeof(salt));
    size_t keyLen = strlen((char*)key);
    char* xorpass = xor_with_key(key, keyLen);
    char* b64pass = base64_encode(xorpass, keyLen);

    /*
    printf("\n[TEST] Random XOR key:\n%s\n", xorKey);
    printf("\n[TEST] Base64 random XOR key:\n%s\n", b64xorKey);
    //printf("\n[TEST] XORRED shellcode:\n%s\n", xorshell_enc);
    printf("\n[TEST] Base64 XORRED shellcode:\n%s\n", b64shell_enc);
    //printf("\n[TEST] XORRED IV:\n%s\n", xorivEnc);
    printf("\n[TEST] Base64 XORRED IV:\n%s\n", b64ivEnc);
    //printf("\n[TEST] XORRED password:\n%s\n", xorpass);
    printf("\n[TEST] Base64 XORRED password:\n%s\n", b64pass);
    printf("\n[TEST] Lenght of base64 password: %d\n", strlen((char*)b64pass));
    //printf("\n[TEST] XORRED salt:\n%s\n", xorsalt);
    printf("\n[TEST] Base64 XORRED salt:\n%s\n", b64salt);
    */

    // Print banner for begin variables used in decrypter
    printf(COLOR_BOLD_GREEN"\n--------------------BEGIN DECRYPTER VARIABLES--------------------\n"COLOR_OFF);

    // Print the generated XOR key
    printf("\n[+] Randomly generated and printable XOR key; 16 bytes:\n");
    printf("HEX: ");
    printf(COLOR_BOLD_WHITE "\"%s\"\n" COLOR_OFF, xorKey);
    printf("B64: "COLOR_BOLD_WHITE "\"%s\"\n" COLOR_OFF, b64xorKey);

    // Print the length of the original shellcode
    printf("\n[+] Original shellcode length:\n" COLOR_BOLD_WHITE "%d bytes\n" COLOR_OFF, lenShell);

    // Print the shellcode
    printf("\n[+] Base64 XORRED encrypted shellcode:\n");
    printf(COLOR_BOLD_WHITE);
    pretty_print_base64(b64shell_enc);
    printf(COLOR_OFF);

    // Print the IV in hexadecimal format for use in decryption
    printf("\n[+] HEX and Base64 XORRED IV used for encryption:\n");
    printf("HEX: ");
    printf(COLOR_BOLD_WHITE "\"");
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        printf("\\x%02X", ivEnc[i]);
    }
    printf("\"\n" COLOR_OFF);
    printf("B64: "COLOR_BOLD_WHITE "\"%s\"\n" COLOR_OFF, b64ivEnc);

    // Print the password in hex
    printf("\n[+] HEX and Base64 XORRED password used for encryption:\n");
    printf("HEX: ");
    printf(COLOR_BOLD_WHITE "\"");
    for (int i = 0; i < lenKey; i++) {
        printf("\\x%02X", key[i]);
    }
    printf("\"\n" COLOR_OFF);
    printf("B64: "COLOR_BOLD_WHITE "\"%s\"\n" COLOR_OFF, b64pass);

    // Print the salt used
    printf("\n[+] HEX and Base64 XORRED salt used for encryption:\n");
    printf("HEX: ");
    printf(COLOR_BOLD_WHITE "\"");
    for (int i = 0; i < sizeof(salt); i++) {
        printf("\\x%02X", salt[i]);
    }
    printf("\"\n" COLOR_OFF);
    printf("B64: "COLOR_BOLD_WHITE "\"%s\"\n" COLOR_OFF, b64salt);

    // Print banner for end variables used in decrypter
    printf(COLOR_BOLD_GREEN"\n--------------------END DECRYPTER VARIABLES----------------------\n\n"COLOR_OFF);

    // Clean up sensitive information
    memset(key, 0, lenKey);  // Clear the key after use
    EVP_CIPHER_CTX_free(ctx);
    free(shell_enc);
    free(badChars);

    return 0;
}

char* readFile(const char* fileName, int* fileSize) {
    FILE* file = fopen(fileName, "rb");
    if (!file) {
        perror("[!] Error opening file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* data = malloc(size + 1);
    if (!data) {
        perror("[!] malloc failed");
        fclose(file);
        return NULL;
    }

    size_t readSize = fread(data, 1, size, file);
    if (readSize != size) {
        perror("[!] Error reading file");
        free(data);
        fclose(file);
        return NULL;
    }

    data[size] = '\0';
    *fileSize = size;
    fclose(file);
    return data;
}

int contains_bad_characters(const unsigned char* data, int len, unsigned char* badChars, int badCharsLen) {
    if (badChars == NULL || badCharsLen == 0) {
        return 0;  // No bad characters to check
    }

    for (int i = 0; i < len; i++) {
        for (int j = 0; j < badCharsLen; j++) {
            if (data[i] == badChars[j]) {
                return 1;  // Bad character found
            }
        }
    }

    return 0;  // No bad characters found
}

// Function to print data in hex format with bad characters highlighted, and print on multiple lines.
static void print_data(const char* title, const void* data, int len, int is_oneliner, unsigned char* badChars, int badCharsLen, int line_width)
{
    printf("%s:\n", title);
    unsigned char* p = (unsigned char*)data;

    // Calculate how many hex values fit in a line (each "\xXX" takes 4 characters)
    int chars_per_line = line_width / 4;  // Since each "\xXX" is 4 chars long

    if (is_oneliner) {
        printf("\"");
        for (int i = 0; i < len; i++) {
            int isBadChar = 0;
            for (int j = 0; j < badCharsLen; j++) {
                if (p[i] == badChars[j]) {
                    isBadChar = 1;
                    break;
                }
            }
            if (isBadChar) {
                printf(COLOR_BOLD_RED "\\x%02X" COLOR_OFF, p[i]);  // Red color for bad char
            }
            else {
                printf("\\x%02X", p[i]);
            }
        }
        printf("\"\n");
    }
    else {
        printf("\""); // Start the first line with a quote
        int char_count = 0;

        for (int i = 0; i < len; i++) {
            int isBadChar = 0;
            for (int j = 0; j < badCharsLen; j++) {
                if (p[i] == badChars[j]) {
                    isBadChar = 1;
                    break;
                }
            }

            // Print the current hex value with red if it's a bad character
            if (isBadChar) {
                printf(COLOR_BOLD_RED "\\x%02X" COLOR_OFF, p[i]);
            }
            else {
                printf("\\x%02X", p[i]);
            }

            // Increment the character count (4 chars per hex value)
            char_count += 4;

            // If we've reached the line width, print a closing quote and start a new line
            if (char_count >= line_width || i == len - 1) {
                printf("\"");
                printf("\n");  // Move to the next line
                if (i != len - 1) {
                    printf("\"");  // Start the next line with a quote
                }
                char_count = 0;  // Reset the character count for the new line
            }
        }
    }
}

unsigned char* secure_getpass(const char* prompt) {
    // Print prompt to user
    printf("%s", prompt);

    // Allocate a buffer for the password input
    unsigned char* pass = malloc(128);
    int i = 0;

    // Use _getch to read characters one by one without echoing
    while (1) {
        char ch = _getch();
        if (ch == '\r' || ch == '\n') {  // Enter key pressed
            pass[i] = '\0';  // Null terminate the string
            break;
        }
        else if (ch == '\b' && i > 0) {  // Backspace
            i--;
            printf("\b \b");  // Remove last character from console
        }
        else {
            pass[i++] = ch;
            printf("*");  // Show "*" for each character typed
        }
    }

    printf("\n");  // Move to the next line
    return pass;
}

// Pretty print base64
void pretty_print_base64(const char* b64str) {
    int len = strlen(b64str);
    int currentLineLength = 0;

    // Iterate over the Base64 string
    printf("\"");  // Start the first line with a quote
    for (int i = 0; i < len; i++) {
        // Print the Base64 character
        printf("%c", b64str[i]);

        // Update the current line length
        currentLineLength++;

        // If we've reached the max line width, break to the next line
        if (currentLineLength >= LINE_WIDTH) {
            printf("\"\n\"");  // Close the current line with a quote and start a new line with a quote
            currentLineLength = 0;  // Reset the line length counter
        }
    }
    printf("\"\n");  // Close the last line with a quote
}

// Function to enable Virtual Terminal Processing
static void enableAnsiEscapeSequences() {
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdout == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error getting stdout handle\n");
        return;
    }

    // Get the current console mode
    DWORD dwMode;
    if (!GetConsoleMode(hStdout, &dwMode)) {
        fprintf(stderr, "Error getting console mode\n");
        return;
    }

    // Enable Virtual Terminal Processing (ANSI codes support)
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;

    if (!SetConsoleMode(hStdout, dwMode)) {
        fprintf(stderr, "Error setting console mode\n");
        return;
    }
}

void gen_xor_key(unsigned char* xorKey) {
    for (int i = 0; i < XOR_KEY_SIZE; i++) {
        unsigned char randByte;
        // Keep generating random bytes until we get a printable one
        do {
            if (!RAND_bytes(&randByte, 1)) {
                fprintf(stderr, "[!] Error generating random byte\n");
                exit(-1);
            }
        } while (randByte < 32 || randByte > 126);  // Printable ASCII range

        xorKey[i] = randByte;
    }
}

// XOR function
char* xor_with_key(const unsigned char* data, size_t len) {
    // Allocate memory for the XOR-ed result
    unsigned char* xordata = (unsigned char*)malloc(len);
    if (xordata == NULL) {
        fprintf(stderr, "[!] Error allocating memory for XOR result\n");
        exit(-1);
    }

    // Perform the XOR operation on each byte
    for (size_t i = 0; i < len; i++) {
        xordata[i] = data[i] ^ xorKey[i % XOR_KEY_SIZE];
    }

    return (char*)xordata;
}

// Function to base64 encode a buffer
char* base64_encode(const unsigned char* input, size_t length) {
    // Calculate the required size for base64 encoding
    int encodedLength = 4 * ((length + 2) / 3);  // Base64 encoding increases the size by approximately 33%

    // Allocate memory for the encoded string, including space for the null terminator
    char* encoded = (char*)malloc(encodedLength + 1);
    if (encoded == NULL) {
        fprintf(stderr, "[!] Error allocating memory for base64 encoding\n");
        exit(-1);
    }

    // Perform the base64 encoding
    int result = EVP_EncodeBlock((unsigned char*)encoded, input, length);
    if (result < 0) {
        fprintf(stderr, "[!] Error during base64 encoding\n");
        free(encoded);
        exit(-1);
    }

    // Null-terminate the string
    encoded[result] = '\0';
    return encoded;
}