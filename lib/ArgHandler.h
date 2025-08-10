//
// Created by julian on 8/10/25.
//

#ifndef TROJANLETTER_ARGHANDLER_H
#define TROJANLETTER_ARGHANDLER_H
#include <string>
#include <unordered_map>

namespace tl {
    class ArgHandler {
        std::unordered_map<std::string, std::string> options;

        ArgHandler() = default;

    public:
        static ArgHandler fromArgs(int argc, char *argv[]);

        bool hasOption(const std::string &option) const;

        std::string getOption(const std::string &option) const;

        static void printHelp();
    };
}

#endif //TROJANLETTER_ARGHANDLER_H
