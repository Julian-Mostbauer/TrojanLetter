//
// Created by julian on 8/11/25.
//

#ifndef TROJANLETTER_CHACHA20POLY1305ENCRYPTOR_H
#define TROJANLETTER_CHACHA20POLY1305ENCRYPTOR_H


#include "Encryptor.h"
#include </home/julian/GlobalCppLibs/cryptopp890/osrng.h>
#include <string>

namespace tl::Encryption {
    class ChaCha20Poly1305Encryptor final : public Encryptor {
    public:
        // passphrase is the user-provided key material (we will derive a symmetric key)
        explicit ChaCha20Poly1305Encryptor(std::string passphrase);

        ~ChaCha20Poly1305Encryptor() override = default;

        [[nodiscard]] std::string encrypt(const std::string &data) const override;

        [[nodiscard]] std::string decrypt(const std::string &data) const override;

    private:
        std::string passphrase;

        static constexpr size_t KEY_LEN = 32; // 256 bit
        static constexpr size_t SALT_LEN = 16;
        static constexpr size_t NONCE_LEN = 12; // IETF nonce for ChaCha20-Poly1305
        static constexpr uint32_t PBKDF2_ITERS = 200000; // tune per target device
    };
} // namespace tl::Encryption

#endif //TROJANLETTER_CHACHA20POLY1305ENCRYPTOR_H
