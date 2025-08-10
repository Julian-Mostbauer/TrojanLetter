//
// Created by julian on 8/10/25.
//

#include "../lib/ArgHandler.h"

#include <iostream>
#include <ostream>

using std::cout;

namespace tl {
    ArgHandler ArgHandler::fromArgs(const int argc, char *argv[]) {
        ArgHandler handler;
        for (int i = 1; i < argc; ++i) {
            if (std::string arg = argv[i]; arg == "-h" || arg == "--help") {
                handler.options["help"] = "1";
            } else if (arg == "-v" || arg == "--version") {
                handler.options["version"] = "1";
            } else if (arg == "-e" || arg == "--encrypt") {
                if (i + 1 >= argc) throw std::runtime_error("Missing value for --encrypt");
                handler.options["encrypt"] = argv[++i];
            } else if (arg == "-d" || arg == "--decrypt") {
                if (i + 1 >= argc) throw std::runtime_error("Missing value for --decrypt");
                handler.options["decrypt"] = argv[++i];
            } else if (arg == "-k" || arg == "--key") {
                if (i + 1 >= argc) throw std::runtime_error("Missing value for --key");
                handler.options["key"] = argv[++i];
            } else if (arg == "-s" || arg == "--start") {
                if (i + 1 >= argc) throw std::runtime_error("Missing value for --start");
                handler.options["start"] = argv[++i];
            } else if (arg == "-m" || arg == "--mode") {
                if (i + 1 >= argc) throw std::runtime_error("Missing value for --mode");
                handler.options["mode"] = argv[++i];
            } else if (arg == "-i" || arg == "--input" || arg == "-f") {
                if (i + 1 >= argc) throw std::runtime_error("Missing value for --input");
                handler.options["input"] = argv[++i];
            } else if (arg == "-t" || arg == "--text") {
                if (i + 1 >= argc) throw std::runtime_error("Missing value for --text");
                handler.options["text"] = argv[++i];
            } else {
                throw std::runtime_error("Unknown argument: " + arg);
            }
        }
        return handler;
    }

    bool ArgHandler::hasOption(const std::string &option) const {
        return options.contains(option);
    }

    std::string ArgHandler::getOption(const std::string &option) const {
        if (const auto it = options.find(option); it != options.end()) {
            return it->second;
        }
        return "";
    }

    void ArgHandler::printHelp() {
        cout << "================================================================\n";
        cout << "TrojanLetter - Container File Encryption/Decryption Tool\n";
        cout << "----------------------------------------------------------------\n";
        cout << "Usage: ./trojanletter [options]\n";
        cout << "Options:\n";
        cout << "  -h, --help\t\tShow this help message and exit\n";
        cout << "  -v, --version\t\tShow version information and exit\n";
        cout << "  -e, --encrypt <container>\tEncrypt the specified container file\n";
        cout << "  -d, --decrypt <container>\tDecrypt the specified container file\n";
        cout << "  -k, --key <key>\tSpecify encryption key\t required for en&de\n";
        cout << "  -s, --start <byte>\tStart byte in container file for data\t required for en&de\n";
        cout << "  -m, --mode <insert|override>\tInsert or override data in container file\t required for en\n";
        cout << "  -i, --input <file>\tSpecify file to insert into container\t required for en\n";
        cout << "  -t, --text <text>\tSpecify plain text to insert into container\t required for en\n";
        cout << "----------------------------------------------------------------\n";
        cout << "Examples:\n";
        cout << "  ./trojanletter -e mycontainer.trojan -k mysecretkey -s 152 -m override -t \"my secret message\"\n";
        cout << "  ./trojanletter -e mycontainer.trojan -k mysecretkey -s 152 -m insert -f ./my_message.txt\n";
        cout << "  ./trojanletter -d mycontainer.trojan -k mysecretkey -s 152\n";
        cout << "================================================================" << std::endl;
    }
}
