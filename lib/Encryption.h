//
// Created by julian on 8/10/25.
//

#ifndef TROJANLETTER_ENCRYPTION_H
#define TROJANLETTER_ENCRYPTION_H

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace tl {
    constexpr std::size_t kChunkSize = 512 * 1024 * 1024; // 512MB (tunable)
    inline const std::string kEndOfDataMarker = "\0END_OF_DATA\0";

    enum class ContainerStuffingMode { Insert, Overwrite };

    struct MessageData {
        bool isFilePath;
        std::string value;

        static MessageData fromFile(std::string path) { return {true, std::move(path)}; }
        static MessageData fromText(std::string text) { return {false, std::move(text)}; }
    };

    class Encryption {
    public:
        // High-level APIs
        static void encryptFile(std::string_view containerFile, std::string_view key, std::uint64_t offset,
                                ContainerStuffingMode mode, const MessageData &message);

        static void decryptFile(std::string_view containerFile, std::string_view key, std::uint64_t offset,
                                std::string_view outFile = "");

    private:
        // helpers
        static std::ifstream openInput(std::string_view path);

        static std::ofstream openOutput(std::string_view path);

        static void copyN(std::ifstream &in, std::ofstream &out, std::uint64_t bytesToCopy);

        static void copyRemaining(std::ifstream &in, std::ofstream &out);

        static void xorTransformInPlace(char *data, std::size_t size, const std::string &key, bool reverse = false);

        static std::vector<char> encryptedMarker(const std::string &key);

        // mode implementations
        static void encryptInsert(std::string_view containerFile, std::string_view packagedFile, const std::string &key,
                                  std::uint64_t offset, const MessageData &message);

        static void encryptOverwrite(std::string_view containerFile, std::string_view packagedFile,
                                     const std::string &key,
                                     std::uint64_t offset, const MessageData &message);
    };
} // namespace tl

#endif // TROJANLETTER_ENCRYPTION_H
