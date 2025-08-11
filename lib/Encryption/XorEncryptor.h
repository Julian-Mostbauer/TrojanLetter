//
// Created by julian on 8/10/25.
//

#ifndef TROJANLETTER_XORENCRYPTOR_H
#define TROJANLETTER_XORENCRYPTOR_H
#include "Encryptor.h"

namespace tl::Encryption {
    class XorEncryptor final : public Encryptor {
    public:
        explicit XorEncryptor(const std::string &key)
            : Encryptor(key) {
        }

        [[nodiscard]] std::string encrypt(const std::string &data) const override;

        [[nodiscard]] std::string decrypt(const std::string &data) const override;

    };
}
#endif //TROJANLETTER_XORENCRYPTOR_H
