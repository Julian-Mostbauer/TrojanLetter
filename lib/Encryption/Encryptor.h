//
// Created by julian on 8/10/25.
//

#ifndef TROJANLETTER_ENCRYPTOR_H
#define TROJANLETTER_ENCRYPTOR_H
#include <memory>
#include <string>

namespace tl::Encryption {
    enum class EncryptorType {
        Xor,
    };

    class Encryptor {
    protected:
        Encryptor() = default;

    public:
        virtual ~Encryptor() = default;

        virtual std::string encrypt(const std::string &data,
                                    const std::string &key) = 0;

        virtual std::string decrypt(const std::string &data,
                                    const std::string &key) = 0;


        virtual void encrypt(char *data, size_t size,
                             const std::string &key) = 0;

        virtual void decrypt(char *data, size_t size,
                             const std::string &key) = 0;

        static std::unique_ptr<Encryptor> createEncryptor(const EncryptorType &type);
    };
}

#endif //TROJANLETTER_ENCRYPTOR_H
