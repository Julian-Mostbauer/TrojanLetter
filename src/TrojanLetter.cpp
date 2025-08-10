//
// Created by julian on 8/10/25.
//

#include "../lib/TrojanLetter.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <ostream>

#include "Injector.h"


namespace tl {
    MessageData getMessageData(const ArgHandler &argHandler) {
        const std::string data = argHandler.getOption("text") +
                                 argHandler.getOption("input");

        if (data.empty())
            throw std::runtime_error(
                "Message data is required! See help for options.");

        if (argHandler.hasOption("text"))
            return MessageData::fromText(data);

        if (argHandler.hasOption("input"))
            return MessageData::fromFile(data);

        throw std::runtime_error(
            "Invalid message data option. Use -t/--text for inline text or -f/--file for a file path.");
    }

    InjectionMode getInjectionMode(const ArgHandler &argHandler) {
        const std::string mode = argHandler.getOption("mode");
        if (mode.empty())
            throw std::runtime_error("Stuffing mode is required.");

        if (mode == "insert")
            return InjectionMode::Insert;
        if (mode == "overwrite")
            return InjectionMode::Overwrite;

        throw std::runtime_error("Invalid stuffing mode: " + mode);
    }

    size_t getStartByte(const ArgHandler &argHandler) {
        const std::string startByte = argHandler.getOption("start");
        if (startByte.empty())
            throw std::runtime_error("Start byte is required.");

        try {
            return stoull(startByte);
        } catch (const std::invalid_argument &) {
            throw std::runtime_error("Invalid start byte: " + startByte);
        } catch (const std::out_of_range &) {
            throw std::runtime_error("Start byte out of range: " + startByte);
        }
    }

    void TrojanLetter::runWithArgs(const ArgHandler &argHandler) {
        if (argHandler.hasOption("help")) {
            ArgHandler::printHelp();
            return;
        }

        if (argHandler.hasOption("version")) {
            std::cout << "Version 1.0.0" << std::endl;
            return;
        }

        if (argHandler.hasOption("verbose")) {
            argHandler.printCollectedOptions();
        }

        if (argHandler.hasOption("decrypt")) {
            const auto containerFile = argHandler.getOption("decrypt");
            const auto key = argHandler.getOption("key");
            const auto startByte = getStartByte(argHandler);

            if (containerFile.empty() || key.empty())
                throw std::runtime_error("Container file, key, and start byte are required for decryption.");

            if (!std::filesystem::exists(containerFile))
                throw std::runtime_error("Container file does not exist: " + containerFile);

            const auto encryptor = Encryption::Encryptor::createEncryptor(key, Encryption::EncryptorType::Xor);

            Injector::extract(containerFile, encryptor, startByte);
            std::cout << "Decryption completed successfully." << std::endl;
            return;
        }

        if (argHandler.hasOption("encrypt")) {
            const auto containerFile = argHandler.getOption("encrypt");
            const auto key = argHandler.getOption("key");
            const auto startByte = getStartByte(argHandler);
            const auto mode = getInjectionMode(argHandler);
            const auto data = getMessageData(argHandler);

            if (containerFile.empty() || key.empty())
                throw std::runtime_error(
                    "Container file, key, start byte, mode, and message data are required for encryption.");

            const auto encryptor = Encryption::Encryptor::createEncryptor(key, Encryption::EncryptorType::Xor);

            Injector::inject(containerFile, data, encryptor, startByte, mode);
            std::cout << "Encryption completed successfully." << std::endl;
            return;
        }

        std::cerr << "Unrecognized command line options." << std::endl;
        ArgHandler::printHelp();
    }
}
