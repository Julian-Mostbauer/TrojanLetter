//
// Created by julian on 8/10/25.
//

#ifndef TROJANLETTER_INJECTOR_H
#define TROJANLETTER_INJECTOR_H
#include <string>
#include <utility>

namespace tl {
    enum class InjectionMode {
        Overwrite,
        Insert,
    };

    struct MessageData {
        std::string data;
        bool isPath;

        static MessageData fromText(const std::string &text) noexcept {
            return {text, false};
        }

        static MessageData fromFile(const std::string &filePath) noexcept {
            return {filePath, true};
        }

    private:
        MessageData(std::string text, const bool isFilePath) : data(std::move(text)), isPath(isFilePath) {
        }
    };

    class Injector {
        static inline const std::string kEndOfMessageMarker = "TROJANLETTER_END_OF_MESSAGE";
    public:
        static void extract(const std::string &containerFile, const std::string &key, size_t startByte);

        static void inject(const std::string &containerPath,
                           const std::string &key,
                           size_t startByte,
                           const MessageData& messageData,
                           InjectionMode injectionMode);
    };
}

#endif //TROJANLETTER_INJECTOR_H
