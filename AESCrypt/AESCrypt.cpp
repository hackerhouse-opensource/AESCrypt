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

class AESCrypt {
public:
    AESCrypt(const wchar_t* filename, const std::wstring& password, const std::wstring& action) :
        filename(filename), password(password), action(action) {}

    void Run() {
        try {
            if (action == L"encrypt") {
                EncryptFile();
            }
            else if (action == L"decrypt") {
                DecryptFile();
            }
            else {
                std::wcerr << L"Invalid action. Use 'encrypt' or 'decrypt'." << std::endl;
            }
        }
        catch (const std::exception& ex) {
            std::cerr << "Error: " << ex.what() << std::endl;
        }
    }

private:
    const wchar_t* filename;
    std::wstring password;
    std::wstring action;

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

    std::vector<BYTE> DeriveKey() {
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

    std::vector<BYTE> ReadFileContent() {
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Error opening file for reading content.");
        }
        std::vector<BYTE> content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        return content;
    }

    void WriteFileContent(const std::vector<BYTE>& content, const wchar_t* outputFilename) {
        std::ofstream file(outputFilename, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Error opening file for writing content.");
        }
        file.write(reinterpret_cast<const char*>(content.data()), content.size());
    }

    void EncryptFile() {
        PrintOperationDetails(L"Encrypting file");
        std::vector<BYTE> fileContent = ReadFileContent();
        std::vector<BYTE> key = DeriveKey();
        std::vector<BYTE> iv(16);
        GenerateRandomBytes(iv);
        std::vector<BYTE> originalIV = iv;
        BCRYPT_ALG_HANDLE encAlgHandle;
        CheckStatus(L"BCryptOpenAlgorithmProvider failed", BCryptOpenAlgorithmProvider(&encAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0));
        CheckStatus(L"BCryptSetProperty failed", BCryptSetProperty(encAlgHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0));
        BCRYPT_KEY_HANDLE keyHandle;
        CheckStatus(L"BCryptGenerateSymmetricKey failed", BCryptGenerateSymmetricKey(encAlgHandle, &keyHandle, NULL, 0, key.data(), static_cast<ULONG>(key.size()), 0));
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
            BCRYPT_BLOCK_PADDING
        ));
        std::vector<BYTE> cipherText(cbCipherText);
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
            BCRYPT_BLOCK_PADDING
        ));
        BCryptDestroyKey(keyHandle);
        BCryptCloseAlgorithmProvider(encAlgHandle, 0);
        std::vector<BYTE> encryptedContent;
        encryptedContent.insert(encryptedContent.end(), originalIV.begin(), originalIV.end());
        encryptedContent.insert(encryptedContent.end(), cipherText.begin(), cipherText.end());
        std::wstring outputFilename = std::wstring(filename) + L".enc";
        WriteFileContent(encryptedContent, outputFilename.c_str());
        std::wcout << L"Encryption successful." << std::endl;
    }

    void DecryptFile() {
        PrintOperationDetails(L"Decrypting file");
        std::vector<BYTE> encryptedContentBytes = ReadFileContent();
        if (encryptedContentBytes.size() < 16) {
            throw std::runtime_error("Invalid file format");
        }
        std::vector<BYTE> iv(encryptedContentBytes.begin(), encryptedContentBytes.begin() + 16);
        std::wcout << L"IV: " << std::endl;
        PrintHexDump(iv.data(), iv.size());
        std::vector<BYTE> cipherText(encryptedContentBytes.begin() + 16, encryptedContentBytes.end());
        std::vector<BYTE> key = DeriveKey();
        BCRYPT_ALG_HANDLE decAlgHandle;
        CheckStatus(L"BCryptOpenAlgorithmProvider failed", BCryptOpenAlgorithmProvider(&decAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0));
        CheckStatus(L"BCryptSetProperty failed", BCryptSetProperty(decAlgHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0));
        BCRYPT_KEY_HANDLE keyHandle;
        CheckStatus(L"BCryptGenerateSymmetricKey failed", BCryptGenerateSymmetricKey(decAlgHandle, &keyHandle, NULL, 0, key.data(), static_cast<ULONG>(key.size()), 0));
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
            BCRYPT_BLOCK_PADDING
        );
        if (NT_SUCCESS(status)) {
            BCryptDestroyKey(keyHandle);
            BCryptCloseAlgorithmProvider(decAlgHandle, 0);
            decryptedText.resize(cbData);
            std::wstring outputFilename = std::wstring(filename) + L".dec";
            WriteFileContent(decryptedText, outputFilename.c_str());
            std::wcout << L"Decryption successful." << std::endl;
            return;
        }
        BCryptDestroyKey(keyHandle);
        BCryptCloseAlgorithmProvider(decAlgHandle, 0);
        PrintError(L"BCryptDecrypt failed", status);
        throw std::runtime_error("Decryption failed.");
    }
};

int wmain(int argc, wchar_t* argv[]) {
    try {
        if (argc != 4) {
            std::wcerr << L"Usage: " << argv[0] << L" <filename> <password> <encrypt/decrypt>" << std::endl;
            return 1;
        }
        AESCrypt aesCrypt(argv[1], argv[2], argv[3]);
        aesCrypt.Run();
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
#endif // ENCRYPTION_TOOL_H