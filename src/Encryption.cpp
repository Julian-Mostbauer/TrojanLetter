//
// Created by julian on 8/10/25.
//

#include "../lib/Encryption.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <ranges>
#include <vector>

constexpr size_t CHUNK_SIZE = 512 * 1024 * 1024; // 512MB

const std::string Encryption::END_OF_DATA_MARKER = "\0END_OF_DATA\0";

void Encryption::insertFileChunked(const std::string &containerFile, const std::string &messageFile,
                                   const std::string &packagedFile, const std::string &key, size_t start) {
    std::ifstream containerStream(containerFile, std::ios::binary);
    std::ifstream messageStream(messageFile, std::ios::binary);
    std::ofstream outStream(packagedFile, std::ios::binary | std::ios::trunc);

    if (!containerStream.is_open() || !messageStream.is_open() || !outStream.is_open())
        throw std::runtime_error("Failed to open one of the files for chunked insert.");

    // Copy container up to start
    std::vector<char> buffer(CHUNK_SIZE);
    size_t copied = 0;

    while (copied < start) {
        size_t toRead = std::min(CHUNK_SIZE, start - copied);
        containerStream.read(buffer.data(), toRead);
        outStream.write(buffer.data(), containerStream.gcount());
        copied += containerStream.gcount();
    }

    // Write message file (encrypted)
    while (!messageStream.eof()) {
        messageStream.read(buffer.data(), CHUNK_SIZE);
        if (size_t readCount = messageStream.gcount(); readCount > 0) {
            encryptStr(buffer.data(), readCount, key);
            outStream.write(buffer.data(), readCount);
        }
    }

    // Write rest of container
    while (!containerStream.eof()) {
        containerStream.read(buffer.data(), CHUNK_SIZE);
        outStream.write(buffer.data(), containerStream.gcount());
    }

    containerStream.close();
    messageStream.close();
    outStream.close();
}

void Encryption::overwriteFileChunked(const std::string &containerFile, const std::string &messageFile,
                                      const std::string &packagedFile, const std::string &key, size_t start) {
    std::ifstream containerStream(containerFile, std::ios::binary);
    std::ifstream messageStream(messageFile, std::ios::binary);
    std::ofstream outStream(packagedFile, std::ios::binary | std::ios::trunc);

    if (!containerStream.is_open() || !messageStream.is_open() || !outStream.is_open())
        throw std::runtime_error("Failed to open one of the files for chunked overwrite.");

    std::vector<char> buffer(CHUNK_SIZE);
    size_t copied = 0;

    // Copy container up to start
    while (copied < start) {
        size_t toRead = std::min(CHUNK_SIZE, start - copied);
        containerStream.read(buffer.data(), toRead);
        outStream.write(buffer.data(), containerStream.gcount());
        copied += containerStream.gcount();
    }

    // Overwrite with message file (encrypted)
    while (!messageStream.eof()) {
        messageStream.read(buffer.data(), CHUNK_SIZE);
        size_t msgRead = messageStream.gcount();
        encryptStr(buffer.data(), msgRead, key);
        if (containerStream.eof()) {
            outStream.write(buffer.data(), msgRead);
        } else {
            std::vector<char> containerChunk(msgRead);
            containerStream.read(containerChunk.data(), msgRead);
            outStream.write(buffer.data(), msgRead);
        }
        copied += msgRead;
    }

    // Write rest of container if any
    while (!containerStream.eof()) {
        containerStream.read(buffer.data(), CHUNK_SIZE);
        outStream.write(buffer.data(), containerStream.gcount());
    }

    if (!containerStream.eof() && messageStream.eof()) {
        std::cerr << "Warning: Message data exceeded original file size and was written beyond bounds." << std::endl;
    }

    containerStream.close();
    messageStream.close();
    outStream.close();
}

void Encryption::validateEncryptionParams(const std::string &containerFile, const std::string &key,
                                          const MessageData &messageData) {
    if (!std::filesystem::exists(containerFile))
        throw std::runtime_error("Container file does not exist: " + containerFile);

    if (key.empty())
        throw std::runtime_error("Encryption key cannot be empty.");

    if (messageData.value.empty())
        throw std::runtime_error("Message data cannot be empty.");
}


void Encryption::encryptFile(const std::string &containerFile, const std::string &key, size_t start,
                             ContainerStuffingMode mode, const MessageData &messageData) {
    validateEncryptionParams(containerFile, key, messageData);
    const std::string packagedFile = containerFile + "_packaged";
    // Handle message files
    if (messageData.isFilePath) {
        switch (mode) {
            case INSERT: {
                insertFileChunked(containerFile, messageData.value, packagedFile, key, start);
                break;
            }
            case OVERWRITE: {
                overwriteFileChunked(containerFile, messageData.value, packagedFile, key, start);
                break;
            }
            default:
                throw std::runtime_error("Unsupported stuffing mode.");
        }
    }
    // handle plain text data
    else {
        std::ifstream containerStream(containerFile, std::ios::binary);
        if (!containerStream.is_open())
            throw std::runtime_error("Failed to open container file: " + containerFile);

        std::ofstream outStream(packagedFile, std::ios::binary | std::ios::trunc);

        if (!outStream.is_open())
            throw std::runtime_error("Failed to create packaged file: " + packagedFile);

        auto &text = const_cast<std::string &>(messageData.value);

        switch (mode) {
            case INSERT: {
                // Copy container up to start
                containerStream.seekg(0, std::ios::end);
                std::streamsize containerSize = containerStream.tellg();
                containerStream.seekg(0, std::ios::beg);

                if (start > containerSize)
                    throw std::runtime_error("Start position is beyond container file size.");

                std::vector<char> buffer(start);
                containerStream.read(buffer.data(), start);
                outStream.write(buffer.data(), start);

                // Write message text
                std::vector<char> encryptedText(text.begin(), text.end());
                encryptStr(encryptedText.data(), encryptedText.size(), key);
                outStream.write(encryptedText.data(), encryptedText.size());
                std::vector<char> encryptedMarker(END_OF_DATA_MARKER.begin(), END_OF_DATA_MARKER.end());
                encryptStr(encryptedMarker.data(), encryptedMarker.size(), key);
                outStream.write(encryptedMarker.data(), encryptedMarker.size());
                // Write rest of container
                std::vector<char> restBuffer(static_cast<size_t>(containerSize - start));
                containerStream.read(restBuffer.data(), containerSize - start);
                outStream.write(restBuffer.data(), containerSize - start);

                containerStream.close();
                outStream.close();
                break;
            }
            case OVERWRITE: {
                containerStream.seekg(0, std::ios::end);
                std::streamsize containerSize = containerStream.tellg();
                containerStream.seekg(0, std::ios::beg);

                if (start > containerSize)
                    throw std::runtime_error("Start position is beyond container file size.");

                // Copy container up to start
                std::vector<char> buffer(start);
                containerStream.read(buffer.data(), start);
                outStream.write(buffer.data(), start);

                // Overwrite with message text
                size_t overwriteEnd = start + text.size();
                bool extended = false;
                if (overwriteEnd > containerSize)
                    extended = true;

                std::vector<char> encryptedText(text.begin(), text.end());
                encryptStr(encryptedText.data(), encryptedText.size(), key);
                outStream.write(encryptedText.data(), encryptedText.size());
                std::vector<char> encryptedMarker(END_OF_DATA_MARKER.begin(), END_OF_DATA_MARKER.end());
                encryptStr(encryptedMarker.data(), encryptedMarker.size(), key);
                outStream.write(encryptedMarker.data(), encryptedMarker.size());
                // Write rest of container if any
                if (!extended) {
                    std::vector<char> restBuffer(containerSize - overwriteEnd);
                    containerStream.read(restBuffer.data(), containerSize - overwriteEnd);
                    outStream.write(restBuffer.data(), containerSize - overwriteEnd);
                } else
                    std::cerr << "Warning: Message data exceeded original file size and was written beyond bounds." <<
                            std::endl;


                containerStream.close();
                outStream.close();
                break;
            }
            default:
                throw std::runtime_error("Unsupported stuffing mode.");
        }
    }
}

void Encryption::validateDecryptionParams(const std::string &containerFile, const std::string &key) {
    if (!std::filesystem::exists(containerFile))
        throw std::runtime_error("Container file does not exist: " + containerFile);

    if (key.empty())
        throw std::runtime_error("Decryption key cannot be empty.");
}

void Encryption::decryptFile(const std::string &containerFile, const std::string &key, size_t start) {
    validateDecryptionParams(containerFile, key);

    const std::string unpackedFile = containerFile + "_unpacked.txt";
    std::ifstream containerStream(containerFile, std::ios::binary);
    std::ofstream outStream(unpackedFile, std::ios::binary | std::ios::trunc);

    if (!containerStream.is_open() || !outStream.is_open())
        throw std::runtime_error("Failed to open container or output file for decryption.");

    containerStream.seekg(0, std::ios::end);
    std::streamsize containerSize = containerStream.tellg();

    if (start >= containerSize)
        throw std::runtime_error("Start position is beyond container file size.");

    containerStream.seekg(start, std::ios::beg);
    std::vector<char> buffer(CHUNK_SIZE);
    std::vector<char> markerBuffer(END_OF_DATA_MARKER.begin(), END_OF_DATA_MARKER.end());
    size_t markerLen = markerBuffer.size();
    std::vector<char> window;
    window.reserve(markerLen);

    bool found = false;
    while (!containerStream.eof() && !found) {
        containerStream.read(buffer.data(), CHUNK_SIZE);
        size_t readCount = containerStream.gcount();
        if (readCount == 0) break;
        decryptStr(buffer.data(), readCount, key);
        for (size_t i = 0; i < readCount; ++i) {
            window.push_back(buffer[i]);
            if (window.size() > markerLen)
                outStream.put(window.front()), window.erase(window.begin());
            if (window.size() == markerLen && std::equal(window.begin(), window.end(), markerBuffer.begin())) {
                found = true;
                break;
            }
        }
    }

    // Write any remaining data before marker
    if (!found)
        for (char c: window) outStream.put(c);


    containerStream.close();
    outStream.close();
}

void Encryption::encryptStr(char *data, const size_t size, const std::string &key) {
    for (int i = 0; i < size; ++i)
        for (const auto kc: key)
            data[i] ^= kc;

    // This is just a placeholder.
    // Will be replaced with a better one soon. (AES or ChaCha20)
}

void Encryption::decryptStr(char *data, const size_t size, const std::string &key) {
    for (int i = 0; i < size; ++i)
        for (const char it: std::ranges::reverse_view(key))
            data[i] ^= it;
}
