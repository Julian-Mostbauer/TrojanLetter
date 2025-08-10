cmake_minimum_required(VERSION 4.0)
project(TrojanLetter)

set(CMAKE_CXX_STANDARD 20)

add_executable(TrojanLetter src/main.cpp
        src/ArgHandler.cpp
        lib/ArgHandler.h
        src/TrojanLetter.cpp
        lib/TrojanLetter.h
        src/Encryption/Encryptor.cpp
        lib/Encryption/Encryptor.h
        src/Encryption/XorEncryptor.cpp
        lib/Encryption/XorEncryptor.h
        lib/Injector.h
        src/Injector.cpp
)

add_executable(TrojanLetterEncryptionTests tests/EncryptionTests.cpp
        src/Encryption/Encryptor.cpp
        lib/Encryption/Encryptor.h
        src/Encryption/XorEncryptor.cpp
        lib/Encryption/XorEncryptor.h
        /home/julian/GlobalCppLibs/catch2/catch.hpp
        /home/julian/GlobalCppLibs/catch2/catch.cpp
)

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