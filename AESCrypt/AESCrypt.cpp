/* AESCrypt
*  ========
* Takes a file on the command line and encrypts it with AES-256
* using a password and Microsoft Cryptography API. It can also
* take a password and decrypt the file. 
* 
* https://hacker.house
*/
#ifndef ENCRYPTION_TOOL_H
#define ENCRYPTION_TOOL_H

#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

// Utility function for vector conversion
template <typename T, typename U>
std::vector<T> ConvertToVector(const std::vector<U>& input) {
    return std::vector<T>(input.begin(), input.end());
}

// Overload for cases where T and U are the same type
template <typename T>
std::vector<T> ConvertToVector(const std::vector<T>& input) {
    return input;
}

void PrintError(const wchar_t* msg, NTSTATUS status) {
    std::wcerr << L"Error: " << msg << L" (Error code: 0x" << std::hex << status << L")" << std::endl;
}

void CheckStatus(const wchar_t* msg, NTSTATUS status) {
    if (!NT_SUCCESS(status)) {
        PrintError(msg, status);
        throw std::runtime_error("Operation failed.");
    }
}

void PrintOperationDetails(const wchar_t* operation) {
    std::wcout << L"Performing operation: " << operation << std::endl;
}

void PrintHexDump(const void* data, size_t size) {
    const uint8_t* byteData = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; ++i) {
        std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(byteData[i]) << L" ";
        if ((i + 1) % 16 == 0) {
            std::wcout << std::endl;
        }
    }
    if (size % 16 != 0) {
        std::wcout << std::endl;
    }
}

void GenerateRandomBytes(std::vector<BYTE>& buffer) {
    PrintOperationDetails(L"Generating random bytes");
    BCRYPT_ALG_HANDLE randAlgHandle;
    CheckStatus(L"BCryptOpenAlgorithmProvider failed", BCryptOpenAlgorithmProvider(&randAlgHandle, BCRYPT_RNG_ALGORITHM, NULL, 0));
    if (!buffer.empty()) {
        CheckStatus(L"BCryptGenRandom failed", BCryptGenRandom(randAlgHandle, buffer.data(), static_cast<ULONG>(buffer.size()), 0));
    }
    BCryptCloseAlgorithmProvider(randAlgHandle, 0);
    std::wcout << L"Random bytes generated: " << std::endl;
    PrintHexDump(buffer.data(), buffer.size());
}

std::vector<BYTE> DeriveKey(const std::wstring& password) {
    PrintOperationDetails(L"Deriving key from password");
    BCRYPT_ALG_HANDLE algHandle;
    CheckStatus(L"BCryptOpenAlgorithmProvider failed", BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0));
    BCRYPT_HASH_HANDLE hashHandle;
    CheckStatus(L"BCryptCreateHash failed", BCryptCreateHash(algHandle, &hashHandle, NULL, 0, NULL, 0, 0));
    CheckStatus(L"BCryptHashData failed", BCryptHashData(hashHandle, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(password.c_str())), static_cast<ULONG>(password.size() * sizeof(wchar_t)), 0));
    std::vector<BYTE> keyBuffer(32); // 256 bits for AES-256
    CheckStatus(L"BCryptFinishHash failed", BCryptFinishHash(hashHandle, keyBuffer.data(), static_cast<ULONG>(keyBuffer.size()), 0));
    BCryptDestroyHash(hashHandle);
    BCryptCloseAlgorithmProvider(algHandle, 0);
    std::wcout << L"Derived key: " << std::endl;
    PrintHexDump(keyBuffer.data(), keyBuffer.size());
    return keyBuffer;
}

// file helpers. 
std::vector<BYTE> ReadFileContent(const wchar_t* filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Error opening file for reading content.");
    }
    std::vector<BYTE> content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

void WriteFileContent(const wchar_t* filename, const std::vector<BYTE>& content) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Error opening file for writing content.");
    }
    file.write(reinterpret_cast<const char*>(content.data()), content.size());
}

void EncryptFile(const wchar_t* filename, const std::wstring& password) {
    PrintOperationDetails(L"Encrypting file");
    std::vector<BYTE> fileContent = ReadFileContent(filename);
    std::vector<BYTE> key = DeriveKey(password);
    std::vector<BYTE> iv(16);
    GenerateRandomBytes(iv);
    // Save the original IV used for encryption to store in the file.
    std::vector<BYTE> originalIV = iv;
    BCRYPT_ALG_HANDLE encAlgHandle;
    CheckStatus(L"BCryptOpenAlgorithmProvider failed", BCryptOpenAlgorithmProvider(&encAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0));
    CheckStatus(L"BCryptSetProperty failed", BCryptSetProperty(encAlgHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0));
    BCRYPT_KEY_HANDLE keyHandle;
    CheckStatus(L"BCryptGenerateSymmetricKey failed", BCryptGenerateSymmetricKey(encAlgHandle, &keyHandle, NULL, 0, key.data(), static_cast<ULONG>(key.size()), 0));
    // Determine the size of the encrypted data
    DWORD cbCipherText = 0;
    CheckStatus(L"BCryptEncrypt (determine size) failed", BCryptEncrypt(
        keyHandle,
        fileContent.data(),
        static_cast<ULONG>(fileContent.size()),
        NULL,
        iv.data(),
        static_cast<ULONG>(iv.size()),
        NULL,
        0,
        &cbCipherText,
        BCRYPT_BLOCK_PADDING // Add BCRYPT_BLOCK_PADDING flag here
    ));
    // Create a separate buffer for the encrypted data
    std::vector<BYTE> cipherText(cbCipherText);
    // Encrypt the data
    CheckStatus(L"BCryptEncrypt failed", BCryptEncrypt(
        keyHandle,
        fileContent.data(),
        static_cast<ULONG>(fileContent.size()),
        NULL,
        iv.data(),
        static_cast<ULONG>(iv.size()),
        cipherText.data(),
        cbCipherText,
        &cbCipherText,
        BCRYPT_BLOCK_PADDING // Add BCRYPT_BLOCK_PADDING flag here
    ));
    BCryptDestroyKey(keyHandle);
    BCryptCloseAlgorithmProvider(encAlgHandle, 0);
    // Write original IV and ciphertext to the file
    std::vector<BYTE> encryptedContent;
    encryptedContent.insert(encryptedContent.end(), originalIV.begin(), originalIV.end());
    encryptedContent.insert(encryptedContent.end(), cipherText.begin(), cipherText.end());
    // Construct the output filename with ".enc" extension
    std::wstring outputFilename = std::wstring(filename) + L".enc";
    WriteFileContent(outputFilename.c_str(), encryptedContent);
    std::wcout << L"Encryption successful." << std::endl;
}

void DecryptFile(const wchar_t* filename, const std::wstring& password) {
    PrintOperationDetails(L"Decrypting file");
    std::vector<BYTE> encryptedContentBytes = ReadFileContent(filename);
    // Ensure the file has at least the size of an IV
    if (encryptedContentBytes.size() < 16) {
        throw std::runtime_error("Invalid file format");
    }
    // Extract IV from the beginning of the encrypted content
    std::vector<BYTE> iv(encryptedContentBytes.begin(), encryptedContentBytes.begin() + 16);
    std::wcout << L"IV: " << std::endl;
    PrintHexDump(iv.data(), iv.size());
    // Extract ciphertext from the rest of the encrypted content
    std::vector<BYTE> cipherText(encryptedContentBytes.begin() + 16, encryptedContentBytes.end());
    std::vector<BYTE> key = DeriveKey(password);
    BCRYPT_ALG_HANDLE decAlgHandle;
    CheckStatus(L"BCryptOpenAlgorithmProvider failed", BCryptOpenAlgorithmProvider(&decAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0));
    CheckStatus(L"BCryptSetProperty failed", BCryptSetProperty(decAlgHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0));
    BCRYPT_KEY_HANDLE keyHandle;
    CheckStatus(L"BCryptGenerateSymmetricKey failed", BCryptGenerateSymmetricKey(decAlgHandle, &keyHandle, NULL, 0, key.data(), static_cast<ULONG>(key.size()), 0));
    // Decrypt the data
    std::vector<BYTE> decryptedText(cipherText.size());
    DWORD cbData = 0;
    NTSTATUS status = BCryptDecrypt(
        keyHandle,
        cipherText.data(),
        static_cast<ULONG>(cipherText.size()),
        NULL,
        iv.data(),
        static_cast<ULONG>(iv.size()),
        decryptedText.data(),
        static_cast<ULONG>(decryptedText.size()),
        &cbData,
        BCRYPT_BLOCK_PADDING // Add BCRYPT_BLOCK_PADDING flag here
    );
    if (NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        BCryptCloseAlgorithmProvider(decAlgHandle, 0);
        // Resize the vector to remove potential padding
        decryptedText.resize(cbData);
        std::wstring outputFilename = std::wstring(filename) + L".dec";
        WriteFileContent(outputFilename.c_str(), decryptedText);
        std::wcout << L"Decryption successful." << std::endl;
        return;
    }
    // Handle decryption failure
    BCryptDestroyKey(keyHandle);
    BCryptCloseAlgorithmProvider(decAlgHandle, 0);
    PrintError(L"BCryptDecrypt failed", status);
    throw std::runtime_error("Decryption failed.");
}

int wmain(int argc, wchar_t* argv[]) {
    try {
        if (argc != 4) {
            std::wcerr << L"Usage: " << argv[0] << L" <filename> <password> <encrypt/decrypt>" << std::endl;
            return 1;
        }
        const wchar_t* filename = argv[1];
        std::wstring password = argv[2];
        std::wstring action = argv[3];
        if (action == L"encrypt") {
            EncryptFile(filename, password);
        }
        else if (action == L"decrypt") {
            DecryptFile(filename, password);
        }
        else {
            std::wcerr << L"Invalid action. Use 'encrypt' or 'decrypt'." << std::endl;
            return 1;
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
#endif // ENCRYPTION_TOOL_H