#include "../lib/Injector.h"

#include <fstream>
#include <iostream>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

namespace tl {

    void Injector::inject(const std::string &containerPath,
                           const std::string &key,
                           size_t startByte,
                           const MessageData& messageData,
                           InjectionMode injectionMode) {
        (void)key; // Key not used yet

        if (!fs::exists(containerPath)) {
            throw std::runtime_error("Container file does not exist: " + containerPath);
        }

        // Prepare output path: "container-file"_loaded."original_extension"
        fs::path inputPath(containerPath);
        std::string stem = inputPath.stem().string();
        std::string ext = inputPath.extension().string();
        fs::path outputPath = inputPath.parent_path() / (stem + "_loaded" + ext);

        // Copy original container to output
        fs::copy_file(inputPath, outputPath, fs::copy_options::overwrite_existing);

        // Load the data to inject
        std::string data;
        if (messageData.isPath) {
            std::ifstream in(messageData.data, std::ios::binary);
            if (!in) throw std::runtime_error("Failed to open message file: " + messageData.data);
            data.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        } else {
            data = messageData.data;
        }

        // Append end marker
        data += kEndOfMessageMarker;

        // Read output file into memory
        std::ifstream inFile(outputPath, std::ios::binary);
        std::vector<char> buffer((std::istreambuf_iterator<char>(inFile)), {});
        inFile.close();

        if (startByte > buffer.size()) {
            throw std::out_of_range("Start byte is beyond file size.");
        }

        if (injectionMode == InjectionMode::Overwrite) {
            // Overwrite in place (truncate if data goes beyond file size)
            if (startByte + data.size() > buffer.size()) {
                buffer.resize(startByte + data.size());
            }
            std::copy(data.begin(), data.end(), buffer.begin() + startByte);
        } else { // Insert mode
            buffer.insert(buffer.begin() + startByte, data.begin(), data.end());
        }

        // Write back to output file
        std::ofstream outFile(outputPath, std::ios::binary | std::ios::trunc);
        outFile.write(buffer.data(), buffer.size());
    }

    void Injector::extract(const std::string &containerFile,
                            const std::string &key,
                            size_t startByte) {
        (void)key; // Key not used yet

        if (!fs::exists(containerFile)) {
            throw std::runtime_error("Container file does not exist: " + containerFile);
        }

        // Read the container file
        std::ifstream inFile(containerFile, std::ios::binary);
        if (!inFile) throw std::runtime_error("Failed to open container file: " + containerFile);

        // Seek to start byte
        inFile.seekg(startByte);
        if (!inFile) throw std::runtime_error("Failed to seek to start byte.");

        // Read until end marker
        std::string marker = kEndOfMessageMarker;
        std::string extracted;
        char ch;
        std::string window;

        while (inFile.get(ch)) {
            extracted.push_back(ch);
            window.push_back(ch);
            if (window.size() > marker.size()) {
                window.erase(window.begin());
            }
            if (window == marker) {
                // Remove marker from extracted data
                extracted.resize(extracted.size() - marker.size());
                break;
            }
        }

        // Prepare output path: "loaded-container"_package.txt
        fs::path inputPath(containerFile);
        std::string stem = inputPath.stem().string();
        fs::path outputPath = inputPath.parent_path() / (stem + "_package.txt");

        // Save extracted data
        std::ofstream outFile(outputPath, std::ios::binary);
        outFile.write(extracted.data(), extracted.size());
    }

}
