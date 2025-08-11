#include "../lib/Injector.h"

#include <fstream>
#include <iostream>
#include <vector>
#include <filesystem>
#include <cstring>

namespace fs = std::filesystem;

namespace tl {
    void Injector::inject(const std::string &containerPath,
                          const MessageData &messageData,
                          const std::unique_ptr<Encryption::Encryptor> &encryptor,
                          size_t startByte,
                          InjectionMode injectionMode) {
        if (!fs::exists(containerPath)) {
            throw std::runtime_error("Container file does not exist: " + containerPath);
        }

        fs::path inputPath(containerPath);
        std::string stem = inputPath.stem().string();
        std::string ext = inputPath.extension().string();
        fs::path outputPath = inputPath.parent_path() / (stem + "_loaded" + ext);

        fs::copy_file(inputPath, outputPath, fs::copy_options::overwrite_existing);

        // Load message data (binary-safe)
        std::string plainData;
        if (messageData.isPath) {
            std::ifstream in(messageData.data, std::ios::binary);
            if (!in) throw std::runtime_error("Failed to open message file: " + messageData.data);
            plainData.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        } else {
            plainData = messageData.data;
        }

        // Append marker
        plainData += kEndOfMessageMarker;

        // Encrypt full payload (binary data)
        std::string encryptedData = encryptor->encrypt(plainData);

        // Prepare length prefix (uint64_t). Use memcpy to avoid UB.
        uint64_t cipherSize = static_cast<uint64_t>(encryptedData.size());
        char lenBuf[sizeof(cipherSize)];
        std::memcpy(lenBuf, &cipherSize, sizeof(cipherSize)); // native endianness

        // Read output file into buffer (binary)
        std::ifstream inFile(outputPath, std::ios::binary);
        if (!inFile) throw std::runtime_error("Failed to open output file for reading: " + outputPath.string());
        std::vector<char> buffer((std::istreambuf_iterator<char>(inFile)), {});
        inFile.close();

        if (startByte > buffer.size()) {
            throw std::out_of_range("Start byte is beyond file size.");
        }

        // Data to insert/overwrite: [len|ciphertext]
        std::vector<char> payload;
        payload.insert(payload.end(), lenBuf, lenBuf + sizeof(lenBuf));
        payload.insert(payload.end(), encryptedData.begin(), encryptedData.end());

        if (injectionMode == InjectionMode::Override) {
            if (size_t needed = startByte + payload.size(); needed > buffer.size()) buffer.resize(needed);
            std::ranges::copy(payload, buffer.begin() + startByte);
        } else {
            buffer.insert(buffer.begin() + startByte, payload.begin(), payload.end());
        }

        std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
        if (!outFile) throw std::runtime_error("Failed to open output file for writing: " + outputPath.string());
        outFile.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    }

    void Injector::extract(const std::string &containerFile,
                           const std::unique_ptr<Encryption::Encryptor> &encryptor,
                           size_t startByte) {
        if (!fs::exists(containerFile)) {
            throw std::runtime_error("Container file does not exist: " + containerFile);
        }

        std::ifstream inFile(containerFile, std::ios::binary);
        if (!inFile) throw std::runtime_error("Failed to open container file: " + containerFile);

        // Seek to start byte where we stored [len|ciphertext]
        inFile.seekg(0, std::ios::end);
        std::streamoff fileSize = inFile.tellg();
        if (startByte >= static_cast<uint64_t>(fileSize)) {
            throw std::out_of_range("Start byte is beyond file size.");
        }
        inFile.seekg(static_cast<std::streamoff>(startByte), std::ios::beg);

        // Read length prefix
        uint64_t cipherSize = 0;
        inFile.read(reinterpret_cast<char *>(&cipherSize), sizeof(cipherSize));
        if (inFile.gcount() != static_cast<std::streamsize>(sizeof(cipherSize))) {
            throw std::runtime_error("Failed to read ciphertext length from container.");
        }

        // Basic sanity check
        if (cipherSize == 0 || static_cast<uint64_t>(startByte) + sizeof(cipherSize) + cipherSize > static_cast<
                uint64_t>(fileSize)) {
            throw std::runtime_error("Ciphertext length invalid or goes beyond file bounds.");
        }

        // Read exactly cipherSize bytes
        std::string encryptedData;
        encryptedData.resize(cipherSize);
        inFile.read(encryptedData.data(), static_cast<std::streamsize>(cipherSize));
        if (inFile.gcount() != static_cast<std::streamsize>(cipherSize)) {
            throw std::runtime_error("Failed to read full ciphertext from container.");
        }

        // Decrypt whole segment
        std::string decryptedData = encryptor->decrypt(encryptedData);

        // Find marker in decrypted data
        size_t markerPos = decryptedData.find(kEndOfMessageMarker);
        if (markerPos == std::string::npos) {
            throw std::runtime_error("End-of-message marker not found in decrypted data. Possibly wrong key or start.");
        }

        std::string message = decryptedData.substr(0, markerPos);

        fs::path inputPath(containerFile);
        std::string stem = inputPath.stem().string();
        fs::path outputPath = inputPath.parent_path() / (stem + "_package.txt");

        std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
        if (!outFile) throw std::runtime_error("Failed to open output file for writing: " + outputPath.string());
        outFile.write(message.data(), static_cast<std::streamsize>(message.size()));
    }
}
