cmake_minimum_required(VERSION 4.0)
project(TrojanLetter)

set(CMAKE_CXX_STANDARD 20)

add_executable(TrojanLetter src/main.cpp
        src/ArgHandler.cpp
        lib/ArgHandler.h
        src/TrojanLetter.cpp
        lib/TrojanLetter.h
        src/Encryption.cpp
        lib/Encryption.h)
