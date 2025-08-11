//
// Created by julian on 8/11/25.
//

#include "../../lib/Encryption/ChaCha20Poly1305Encryptor.h"
#include </home/julian/GlobalCppLibs/cryptopp890/chacha.h>
#include </home/julian/GlobalCppLibs/cryptopp890/filters.h>
#include </home/julian/GlobalCppLibs/cryptopp890/pwdbased.h>
#include </home/julian/GlobalCppLibs/cryptopp890/sha.h>
#include </home/julian/GlobalCppLibs/cryptopp890/cryptlib.h>
#include </home/julian/GlobalCppLibs/cryptopp890/secblock.h>
#include </home/julian/GlobalCppLibs/cryptopp890/chachapoly.h>
#include </home/julian/GlobalCppLibs/cryptopp890/osrng.h>
#include <stdexcept>

namespace tl::Encryption {
    using namespace CryptoPP;

    ChaCha20Poly1305Encryptor::ChaCha20Poly1305Encryptor(std::string passphrase)
        : Encryptor(passphrase), passphrase(std::move(passphrase)) {
    }

    // output format: [salt (16)] [nonce (12)] [ciphertext || tag]
    std::string ChaCha20Poly1305Encryptor::encrypt(const std::string &data) const {
        AutoSeededRandomPool rng;

        SecByteBlock salt(SALT_LEN);
        SecByteBlock nonce(NONCE_LEN);
        rng.GenerateBlock(salt, salt.size());
        rng.GenerateBlock(nonce, nonce.size());

        SecByteBlock key(KEY_LEN);
        PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
        pbkdf.DeriveKey(key, key.size(), 0,
                        reinterpret_cast<const byte *>(passphrase.data()), passphrase.size(),
                        salt, salt.size(), PBKDF2_ITERS);

        ChaCha20Poly1305_Final<true> enc;
        enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());

        std::string cipher_and_tag;
        AuthenticatedEncryptionFilter ef(enc,
                                         new StringSink(cipher_and_tag),
                                         false, 16);

        // no AAD used. If you want file metadata authenticated, put it on AAD.
        ef.ChannelPut("AAD", nullptr, 0);
        ef.ChannelMessageEnd("AAD");

        ef.Put(reinterpret_cast<const byte *>(data.data()), data.size());
        ef.MessageEnd();

        // assemble output
        std::string out;
        out.reserve(SALT_LEN + NONCE_LEN + cipher_and_tag.size());
        out.append(reinterpret_cast<const char *>(salt.BytePtr()), SALT_LEN);
        out.append(reinterpret_cast<const char *>(nonce.BytePtr()), NONCE_LEN);
        out.append(cipher_and_tag);
        return out;
    }

    std::string ChaCha20Poly1305Encryptor::decrypt(const std::string &data) const {
        if (data.size() < SALT_LEN + NONCE_LEN + 16) {
            throw std::runtime_error("input too short for ChaCha20-Poly1305 format");
        }

        auto ptr = reinterpret_cast<const byte *>(data.data());
        SecByteBlock salt(ptr, SALT_LEN);
        ptr += SALT_LEN;
        SecByteBlock nonce(ptr, NONCE_LEN);
        ptr += NONCE_LEN;
        size_t ct_len = data.size() - SALT_LEN - NONCE_LEN;
        std::string cipher_and_tag(reinterpret_cast<const char *>(ptr), ct_len);

        SecByteBlock key(KEY_LEN);
        PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
        pbkdf.DeriveKey(key, key.size(), 0,
                        reinterpret_cast<const byte *>(passphrase.data()), passphrase.size(),
                        salt, salt.size(), PBKDF2_ITERS);

        ChaCha20Poly1305_Final<false> dec;
        dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());

        std::string recovered;
        try {
            AuthenticatedDecryptionFilter df(dec,
                                             new StringSink(recovered),
                                             AuthenticatedDecryptionFilter::DEFAULT_FLAGS, 16); // throws on auth fail
            df.ChannelPut("AAD", nullptr, 0);
            df.ChannelMessageEnd("AAD");

            df.Put(reinterpret_cast<const byte *>(cipher_and_tag.data()), cipher_and_tag.size());
            df.MessageEnd();
        } catch (const CryptoPP::Exception &e) {
            throw std::runtime_error(std::string("decryption/authentication failed: ") + e.what());
        }

        return recovered;
    }
} // namespace tl::Encryption
