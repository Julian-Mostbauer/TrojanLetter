//
// Created by julian on 8/10/25.
//

#ifndef TROJANLETTER_XORENCRYPTOR_H
#define TROJANLETTER_XORENCRYPTOR_H
#include "Encryptor.h"

namespace tl::Encryption {
    class XorEncryptor final : public Encryptor {
    public:
        std::string encrypt(const std::string &data, const std::string &key) override;

        std::string decrypt(const std::string &data, const std::string &key) override;

        void encrypt(char *data, size_t size, const std::string &key) override;

        void decrypt(char *data, size_t size, const std::string &key) override;
    };
}
#endif //TROJANLETTER_XORENCRYPTOR_H
