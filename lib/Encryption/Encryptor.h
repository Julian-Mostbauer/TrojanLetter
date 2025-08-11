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
        ChaCha20Poly1305
    };

    /**
     * Converts a string representation of an encryption type to the corresponding EncryptorType enum value.
     * @param type The name of the encryption type as a string.
     * @return The corresponding EncryptorType enum value.
     * @throws std::invalid_argument if the provided type does not match any known encryption type.
     */
    EncryptorType encryptorTypeFromStr(const std::string &type);

    /** Prints the available encryption algorithms to the provided output stream.
     * This function lists all supported encryption algorithms that can be used with the Encryptor class.
     * @param out The output stream to print the available algorithms to.
     */
    void printAvailableAlgorithms(std::ostream &out) noexcept;

    class Encryptor {
    protected:
        std::string key;

        explicit Encryptor(std::string key) : key(std::move(key)) {
        };

    public:
        virtual ~Encryptor() = default;

        /** Encrypts the provided data using the encryption algorithm defined by the derived class.
         * @param data The data to encrypt.
         * @return The encrypted data as a string.
         */
        [[nodiscard]] virtual std::string encrypt(const std::string &data) const = 0;

        /** Decrypts the provided data using the decryption algorithm defined by the derived class.
         * @param data The data to decrypt.
         * @return The decrypted data as a string.
         */
        [[nodiscard]] virtual std::string decrypt(const std::string &data) const = 0;

        /**
         *  Creates an instance of Encryptor based on the specified type.
         *  This method is a factory method that returns a unique pointer to an Encryptor instance
         * @param key The encryption key to use. Will be used in encryption and decryption.
         * @param type The type of encryption to use.
         * @return A unique pointer to an Encryptor instance that matches the specified type.
         */
        static std::unique_ptr<Encryptor> createEncryptor(const std::string &key, const EncryptorType &type);
    };
}

#endif //TROJANLETTER_ENCRYPTOR_H
