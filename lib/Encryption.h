//
// Created by julian on 8/10/25.
//

#ifndef TROJANLETTER_ENCRYPTION_H
#define TROJANLETTER_ENCRYPTION_H
#include <cstdint>
#include <iostream>
#include <utility>


enum ContainerStuffingMode {
    INSERT,
    OVERWRITE,
};

struct MessageData {
    bool isFilePath;
    std::string value;

    static MessageData fromFile(const std::string &filePath) {
        return MessageData(true, filePath);
    }

    static MessageData fromText(const std::string &text) {
        return MessageData(false, text);
    }

private:
    explicit MessageData(const bool isFilePath, std::string value) : isFilePath(isFilePath), value(std::move(value)) {
    };
};

class Encryption {
public:
    static void decryptFile(const std::string &containerFile, const std::string &key, size_t start);

    static void encryptFile(const std::string &containerFile, const std::string &key, size_t start,
                        ContainerStuffingMode mode, const MessageData &messageData) ;

private:
    const static std::string END_OF_DATA_MARKER;
    static void insertFileChunked(const std::string &containerFile, const std::string &messageFile,
                                  const std::string &packagedFile, const std::string &key, size_t start);

    static void overwriteFileChunked(const std::string &containerFile, const std::string &messageFile,
                                     const std::string &packagedFile, const std::string &key, size_t start);

    inline static void validateEncryptionParams(const std::string &containerFile, const std::string &key, const MessageData &messageData);
    inline static void validateDecryptionParams(const std::string &containerFile, const std::string &key);

    static void encryptStr(char *data, size_t size, const std::string &key);
    static void decryptStr(char *data, size_t size, const std::string &key);
};


#endif //TROJANLETTER_ENCRYPTION_H
