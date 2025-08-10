//
// Created by julian on 8/10/25.
//

#include "../../lib/Encryption/XorEncryptor.h"

namespace tl::Encryption {
    std::string XorEncryptor::encrypt(const std::string &data) const {
        std::string encrypted = data;
        for (size_t i = 0; i < data.size(); ++i) {
            encrypted[i] = data[i] ^ key[i % key.size()];
        }
        return encrypted;
    }

    std::string XorEncryptor::decrypt(const std::string &data) const {
        return encrypt(data); // XOR decryption is the same as encryption
    }

    void XorEncryptor::encrypt(char *data, const size_t size) const {
        for (size_t i = 0; i < size; ++i) {
            data[i] ^= key[i % key.size()];
        }
    }

    void XorEncryptor::decrypt(char *data, const size_t size) const {
        encrypt(data, size); // XOR decryption is the same as encryption
    }
}
