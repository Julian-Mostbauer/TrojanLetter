#include "../lib/Injector.h"

#include <fstream>
#include <iostream>
#include <vector>
#include <filesystem>

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

        // Load message data
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

        // Encrypt full payload
        std::string encryptedData = encryptor->encrypt(plainData);

        // Read output file
        std::ifstream inFile(outputPath, std::ios::binary);
        std::vector<char> buffer((std::istreambuf_iterator<char>(inFile)), {});
        inFile.close();

        if (startByte > buffer.size()) {
            throw std::out_of_range("Start byte is beyond file size.");
        }

        if (injectionMode == InjectionMode::Overwrite) {
            if (startByte + encryptedData.size() > buffer.size()) {
                buffer.resize(startByte + encryptedData.size());
            }
            std::copy(encryptedData.begin(), encryptedData.end(), buffer.begin() + startByte);
        } else {
            buffer.insert(buffer.begin() + startByte, encryptedData.begin(), encryptedData.end());
        }

        std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
        outFile.write(buffer.data(), buffer.size());
    }

    void Injector::extract(const std::string &containerFile,
                           const std::unique_ptr<Encryption::Encryptor> &encryptor,
                           size_t startByte) {
        if (!fs::exists(containerFile)) {
            throw std::runtime_error("Container file does not exist: " + containerFile);
        }

        std::ifstream inFile(containerFile, std::ios::binary);
        if (!inFile) throw std::runtime_error("Failed to open container file: " + containerFile);

        inFile.seekg(startByte);
        if (!inFile) throw std::runtime_error("Failed to seek to start byte.");

        // Read everything from startByte to EOF
        std::string encryptedData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());

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

        std::ofstream outFile(outputPath, std::ios::binary);
        outFile.write(message.data(), message.size());
    }
}
