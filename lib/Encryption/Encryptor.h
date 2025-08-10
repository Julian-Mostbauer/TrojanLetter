//
// Created by julian on 8/10/25.
//

#ifndef TROJANLETTER_ENCRYPTOR_H
#define TROJANLETTER_ENCRYPTOR_H
#include <memory>
#include <string>
#include <utility>

namespace tl::Encryption {
    enum class EncryptorType {
        Xor,
    };

    class Encryptor {
    protected:
        std::string key;

        explicit Encryptor(std::string key) : key(std::move(key)) {
        };

    public:
        virtual ~Encryptor() = default;

        [[nodiscard]] virtual std::string encrypt(const std::string &data) const = 0;

        [[nodiscard]] virtual std::string decrypt(const std::string &data) const = 0;


        virtual void encrypt(char *data, size_t size) const = 0;

        virtual void decrypt(char *data, size_t size) const = 0;

        static std::unique_ptr<Encryptor> createEncryptor(const std::string &key, const EncryptorType &type);
    };
}

#endif //TROJANLETTER_ENCRYPTOR_H
