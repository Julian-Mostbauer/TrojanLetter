//
// Created by julian on 8/10/25.
//

#include "../../lib/Encryption/Encryptor.h"

#include <memory>
#include <stdexcept>
#include "../../lib/Encryption/XorEncryptor.h"

namespace tl::Encryption {
    std::unique_ptr<Encryptor> Encryptor::createEncryptor(const EncryptorType &type) {
        switch (type) {
            case EncryptorType::Xor:
                return std::make_unique<XorEncryptor>();
            default:
                throw std::runtime_error("Unknown encryptor type");
        }
    }
}
