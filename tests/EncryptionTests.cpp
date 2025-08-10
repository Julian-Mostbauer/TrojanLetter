//
// Created by julian on 8/10/25.
//
#include "/home/julian/GlobalCppLibs/catch2/catch.hpp"
#include "../lib/Encryption/Encryptor.h"

using namespace tl::Encryption;

TEST_CASE("XorEncryptor encrypts then decrypts results in original data") {
    const auto encryptor = Encryptor::createEncryptor(EncryptorType::Xor);

    std::string data = "Hello, World!";
    const std::string key = "key";
    std::string encrypted = encryptor->encrypt(data, key);
    std::string decrypted = encryptor->decrypt(encrypted, key);
    REQUIRE(decrypted == data);
    REQUIRE(encrypted != data); // Ensure encryption changes the data
}

TEST_CASE("Inplace XorEncryptor encrypts then decrypts results in original data") {
    const auto encryptor = Encryptor::createEncryptor(EncryptorType::Xor);

    const std::string data = "Hello, World!";
    const std::string key = "key";
    const size_t size = data.size();

    encryptor->encrypt(data, key);
    std::string encryptedData = data; // Copy original data to encryptedData

    encryptor->encrypt(encryptedData.data(), size, key);
    REQUIRE(encryptedData != data); // Ensure encryption changes the data

    encryptor->decrypt(encryptedData.data(), size, key);
    REQUIRE(encryptedData == data);
}
