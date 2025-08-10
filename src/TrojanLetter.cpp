//
// Created by julian on 8/10/25.
//

#include "../lib/TrojanLetter.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <ostream>

#include "../lib/Encryption.h"

using namespace std;

MessageData getMessageData(const ArgHandler &argHandler) {
    const string data = argHandler.getOption("-t") + argHandler.getOption("--text") +
                        argHandler.getOption("-f") + argHandler.getOption("--file");

    if (data.empty())
        throw runtime_error(
            "Message data is required. Either use -t/--text for inline text or -f/--file for a file path.");

    if (argHandler.hasOption("-t") || argHandler.hasOption("--text"))
        return MessageData::fromText(data);

    if (argHandler.hasOption("-f") || argHandler.hasOption("--file"))
        return MessageData::fromFile(data);

    throw runtime_error("Invalid message data option. Use -t/--text for inline text or -f/--file for a file path.");
}

ContainerStuffingMode getStuffingMode(const ArgHandler &argHandler) {
    const string mode = argHandler.getOption("-m") + argHandler.getOption("--mode");
    if (mode.empty())
        throw runtime_error("Stuffing mode is required.");

    if (mode == "insert")
        return ContainerStuffingMode::INSERT;
    if (mode == "overwrite")
        return ContainerStuffingMode::OVERWRITE;

    throw runtime_error("Invalid stuffing mode: " + mode);
}

size_t getStartByte(const ArgHandler &argHandler) {
    const string startByte = argHandler.getOption("-s") + argHandler.getOption("--start");
    if (startByte.empty())
        throw runtime_error("Start byte is required.");

    try {
        return stoull(startByte);
    } catch (const std::invalid_argument &) {
        throw runtime_error("Invalid start byte: " + startByte);
    } catch (const std::out_of_range &) {
        throw runtime_error("Start byte out of range: " + startByte);
    }
}

void TrojanLetter::runWithArgs(const ArgHandler &argHandler) {
    if (argHandler.hasOption("-h") || argHandler.hasOption("--help")) {
        ArgHandler::printHelp();
        return;
    }

    if (argHandler.hasOption("-v") || argHandler.hasOption("--version")) {
        cout << "Version 1.0.0" << endl;
        return;
    }

    if (argHandler.hasOption("-d") || argHandler.hasOption("--decrypt")) {
        if (!argHandler.hasOption("-k") || !argHandler.hasOption("-s")) {
            throw runtime_error("Missing required options for decryption.");
        }

        const auto containerFile = argHandler.getOption("-d") + argHandler.getOption("--decrypt");
        const auto key = argHandler.getOption("-k") + argHandler.getOption("--key");
        const auto startByte = getStartByte(argHandler);

        if (containerFile.empty() || key.empty())
            throw runtime_error("Container file, key, and start byte are required for decryption.");

        if (!std::filesystem::exists(containerFile))
            throw runtime_error("Container file does not exist: " + containerFile);

        Encryption::decryptFile(containerFile, key, startByte);
    }

    if (argHandler.hasOption("-e")) {
        if (!argHandler.hasOption("-k") || !argHandler.hasOption("-s") || !argHandler.hasOption("-m"))
            throw runtime_error("Missing required options for encryption.");

        const auto containerFile = argHandler.getOption("-e") + argHandler.getOption("--encrypt");
        const auto key = argHandler.getOption("-k") + argHandler.getOption("--key");
        const auto startByte = getStartByte(argHandler);
        const auto mode = getStuffingMode(argHandler);
        const auto data = getMessageData(argHandler);

        if (containerFile.empty() || key.empty())
            throw runtime_error("Container file, key, start byte, mode, and message data are required for encryption.");

        Encryption::encryptFile(containerFile, key, startByte, mode, data);
    }

    cerr << "Unrecognized command line options." << endl;
    ArgHandler::printHelp();
}
