//
// Created by julian on 8/10/25.
//

#include "../../lib/Encryption/Encryptor.h"

#include <iostream>
#include <memory>
#include <stdexcept>
#include "../../lib/Encryption/XorEncryptor.h"
#include "../../lib/Encryption/ChaCha20Poly1305Encryptor.h"

namespace tl::Encryption {
    EncryptorType encryptorTypeFromStr(const std::string &type) {
        if (type == "Xor")
            return EncryptorType::Xor;

        if (type == "ChaCha20Poly1305")
            return EncryptorType::ChaCha20Poly1305;

        throw std::invalid_argument("Unknown encryptor type: " + type);
    }

    void printAvailableAlgorithms(std::ostream &out) noexcept {
        out << "Available encryption algorithms:\n"
                << "  - Xor: Basic xor encryption. Not recommended.\n"
                << "  - ChaCha20Poly1305: Generally secure. Details can be found https://en.wikipedia.org/wiki/ChaCha20-Poly1305\n";
    }

    std::unique_ptr<Encryptor> Encryptor::createEncryptor(const std::string &key, const EncryptorType &type) {
        switch (type) {
            case EncryptorType::Xor:
                return std::make_unique<XorEncryptor>(key);
            case EncryptorType::ChaCha20Poly1305:
                return std::make_unique<ChaCha20Poly1305Encryptor>(key);
            default:
                throw std::runtime_error("Unknown encryptor type");
        }
    }
}
