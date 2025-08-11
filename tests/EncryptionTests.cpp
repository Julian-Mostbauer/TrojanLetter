//
// Created by julian on 8/10/25.
//
#include "/home/julian/GlobalCppLibs/catch2/catch.hpp"
#include "../lib/Encryption/Encryptor.h"

using namespace tl::Encryption;

TEST_CASE("XorEncryptor encrypts then decrypts results in original data") {
    std::string data = "Hello, World!";
    const std::string key = "key";
    const auto encryptor = Encryptor::createEncryptor(key, EncryptorType::Xor);

    std::string encrypted = encryptor->encrypt(data);
    std::string decrypted = encryptor->decrypt(encrypted);
    REQUIRE(decrypted == data);
    REQUIRE(encrypted != data); // Ensure encryption changes the data
}

TEST_CASE("ChaCha20Poly1305 encrypts then decrypts results in original data") {
    try {
        std::string data = "Hello, World!";
        const std::string key = "key";
        const auto encryptor = Encryptor::createEncryptor(key, EncryptorType::ChaCha20Poly1305);

        std::string encrypted = encryptor->encrypt(data);
        std::string decrypted = encryptor->decrypt(encrypted);

        REQUIRE(decrypted == data);
        REQUIRE(encrypted != data);
    } catch (const std::exception &e) {
        FAIL("Exception thrown: " << e.what());
    }
}
