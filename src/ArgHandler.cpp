//
// Created by julian on 8/10/25.
//

#include "../lib/ArgHandler.h"

#include <iostream>
#include <ostream>

using std::cout;

namespace tl {
    inline std::string ArgHandler::getDefaultValue(const std::string &option) noexcept {
        if (option == "help") return "";
        if (option == "version") return "";
        if (option == "encrypt") return "";
        if (option == "decrypt") return "";
        if (option == "key") return "";
        if (option == "start") return "";
        if (option == "input") return "";
        if (option == "text") return "";
        if (option == "verbose") return "0";
        if (option == "mode") return "insert";
        if (option == "algorithm") return "ChaCha20Poly1305";
        return "";
    }

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
            } else if (arg == "--verbose") {
                handler.options["verbose"] = "1";
            } else if (arg == "-a" || arg == "--algorithm") {
                handler.options["algorithm"] = argv[++i];
            } else if (arg == "--listalg") {
                handler.options["listalg"] = "1";
            } else {
                throw std::runtime_error("Unknown argument: " + arg);
            }
        }
        return handler;
    }

    bool ArgHandler::hasOption(const std::string &option) const noexcept {
        return options.contains(option);
    }

    std::string ArgHandler::getOption(const std::string &option) const noexcept {
        if (const auto it = options.find(option); it != options.end()) {
            return it->second;
        }
        return getDefaultValue(option);
    }

    void ArgHandler::printCollectedOptions(std::ostream &out) const noexcept {
        out << "================================================================\n";
        out << "Collected Options:\n";
        for (const auto &[fst, snd]: options) {
            out << "  " << fst << ": " << snd << "\n";
        }
        out << "================================================================" << std::endl;
    }

    void ArgHandler::printHelp(std::ostream &out) noexcept {
        out << "================================================================\n";
        out << "TrojanLetter - Container File Encryption/Decryption Tool\n";
        out << "----------------------------------------------------------------\n";
        out << "Usage: ./trojanletter [options]\n\n";

        out << "General:\n"
                << "  -h, --help                     Show this help message and exit\n"
                << "  -v, --version                  Show version information and exit\n"
                << "  --list-algorithms              List available encryption algorithms and exit\n"
                << "  --verbose                      Enable verbose logging\n"
                << "\n";

        out << "Encryption:\n"
                << "  -e, --encrypt <container>      Encrypt the container file (no default value)\n"
                << "  -k, --key <key>                Encryption key (no default value)\n"
                << "  -s, --start <byte>             Start byte in container file (no default value)\n"
                << "  -m, --mode <insert|override>   How to insert data into container (default: insert)\n"
                << "        | insert: Insert data after the specified byte position\n"
                << "        | override: Override data after the specified start byte position\n"
                << "        | (Warning) This does not mean the original file will be overridden! All changes will be written to a seperate output file.\n"
                << "  -i, --input <file>             File to insert (no default value)\n"
                << "  -t, --text <text>              Plain text to insert (no default value)\n"
                << "  -a, --algorithm <name>         Encryption algorithm (default: ChaCha20Poly1305)\n"
                << "\n";

        out << "Decryption:\n"
                << "  -d, --decrypt <container>      Decrypt the container file (no default value)\n"
                << "  -k, --key <key>                Encryption key (no default value)\n"
                << "  -s, --start <byte>             Start byte in container file (no default value)\n"
                << "  -a, --algorithm <name>         Encryption algorithm (default: ChaCha20Poly1305)\n"
                << "\n";

        out << "----------------------------------------------------------------\n";
        out << "Examples:\n"
                << "  ./trojanletter -e container.trojan -k mykey -s 152 -m override -t \"secret\"\n"
                << "  ./trojanletter -e container.trojan -k mykey -s 152 -m insert -f ./msg.txt\n"
                << "  ./trojanletter -d container.trojan -k mykey -s 152\n";
        out << "================================================================" << std::endl;
    }
}
