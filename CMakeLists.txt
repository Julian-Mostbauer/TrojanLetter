cmake_minimum_required(VERSION 4.0)
project(TrojanLetter)

set(CMAKE_CXX_STANDARD 20)

add_executable(TrojanLetter
        src/main.cpp
        src/ArgHandler.cpp
        src/TrojanLetter.cpp
        src/Encryption/Encryptor.cpp
        src/Encryption/XorEncryptor.cpp
        src/Injector.cpp
        src/Encryption/ChaCha20Poly1305Encryptor.cpp
)

target_include_directories(TrojanLetter PRIVATE /home/julian/GlobalCppLibs/cryptopp890)
target_link_libraries(TrojanLetter PRIVATE /home/julian/GlobalCppLibs/cryptopp890/libcryptopp.a)

add_executable(TrojanLetterEncryptionTests
        tests/EncryptionTests.cpp
        /home/julian/GlobalCppLibs/catch2/catch.cpp

        src/Encryption/Encryptor.cpp
        src/Encryption/XorEncryptor.cpp
        src/Encryption/ChaCha20Poly1305Encryptor.cpp
)

target_include_directories(TrojanLetterEncryptionTests PRIVATE /home/julian/GlobalCppLibs/cryptopp890)
target_link_libraries(TrojanLetterEncryptionTests PRIVATE /home/julian/GlobalCppLibs/cryptopp890/libcryptopp.a)

target_compile_options(TrojanLetterEncryptionTests PRIVATE -fsanitize=address,undefined -g -O1)
target_link_libraries(TrojanLetterEncryptionTests PRIVATE -fsanitize=address,undefined)


target_compile_options(TrojanLetter PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Werror
)

target_include_directories(TrojanLetter PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)