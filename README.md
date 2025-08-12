# TrojanLetter

## TEMPORARY WARNING!

This project is currently in an early stage of development. 
The code is not yet fully tested and may contain bugs. 
The command line interface is not yet finalized and may change in the future. 

Currently, it is not recommended to use this tool, but you are welcome to try it out and provide feedback.

## Introduction

TrojanLetter is a command-line tool designed to aid in sending secret messages
hidden inside inconspicuous container files. It supports hiding any file or plain text inside a (preferably) bigger
file, such as an image or a video, and can also extract hidden messages from such files. It does not simply insert them
into the container file, but also encrypts them based on the given key and choose encryption algorithm.

### Why "TrojanLetter"?

The name comes from the "[Trojan Horse](https://en.wikipedia.org/wiki/Trojan_Horse)". A seemingly normal everyday
file (the wooden horse) hides a secret message or file. The tool allows you to send messages that are not
easily detectable by casual observers, as they are hidden within container files. This can be useful for
privacy-conscious individuals or anyone who needs to communicate sensitive information without drawing attention.

---

## Features

- Hide any file or plain text inside a container file.
- Extract hidden messages from container files.
- Supports multiple different encryption algorithms. (All symmetric, single key)

---

## Supported Algorithms

Currently, the following encryption algorithms are supported, but more will be added in the future:

- Xor (Not recommended for serious use)
- ChaCha20Poly1305 (probably the best choice for most use cases)

---

## Installation

To install TrojanLetter, you can either build it from source or download a pre-built binary.

### Pre-built Binaries

Check the [releases](https://github.com/Julian-Mostbauer/TrojanLetter/releases) page to see if there are any binaries
for your platform. If available, download the appropriate binary for your operating system and architecture. If you cant
find a suitable binary, you can build it from source as described below, or create
an [issue](https://github.com/Julian-Mostbauer/TrojanLetter/issues) to request a binary for your
platform.

### Building from Source

#### Requirements/Dependencies

- CMake (version 4.0 or higher)
- A C++ compiler (e.g., g++, clang++)
- C++20 support
- [Crypto++](https://www.cryptopp.com/) library compiled to a static library (libcryptopp.a)

#### Steps to Build

1. Clone the repository:

```bash
    git clone https://github.com/Julian-Mostbauer/TrojanLetter
   ```

2. Navigate to the project directory:

```bash
    cd TrojanLetter
  ```

3. Build the project using Cmake:

```bash
    mkdir build && cd build
    cmake ..
    make
  ```

---

## Usage

### Pre-requisites

You and your recipient must agree on a key, starting byte and an encryption algorithm to use. These should be kept
secret, to ensure security. Decide these in person or through a secure channel.

### Command Line Interface

```

Usage: ./trojanletter [options]

General:
-h, --help Show this help message and exit
-v, --version Show version information and exit
--list-algorithms List available encryption algorithms and exit
--verbose Enable verbose logging

Encryption:
-e, --encrypt <container>      Encrypt the container file (no default value)
-k, --key <key>                Encryption key (no default value)
-s, --start <byte>             Start byte in container file (no default value)
-m, --mode <insert|override>   How to insert data into container (default: insert)
  insert: Insert data after the specified byte position
  override: Override data after the specified start byte position
-i, --input <file>             File to insert (no default value)
-t, --text <text>              Plain text to insert (no default value)
-a, --algorithm <name>         Encryption algorithm (default: ChaCha20Poly1305)

Decryption:
-d, --decrypt <container>      Decrypt the container file (no default value)
-k, --key <key>                Encryption key (no default value)
-s, --start <byte>             Start byte in container file (no default value)
-a, --algorithm <name>         Encryption algorithm (default: ChaCha20Poly1305)

----------------------------------------------------------------
Examples:
./trojanletter -e image.png -k "mykey" -s 152000 -m insert -f ./msg.txt -a Xor
./trojanletter -e image.png -k "mykey" -s 152000 -m override -t "my secret message"
./trojanletter -d image_loaded.png -k "mykey" -s 152000
================================================================

```

### Hiding a message

To hide a message inside a container file, use the `-e` option followed by the container file name, the `-k` option for
the encryption key, the `-s` option for the starting byte, and either the `-i` option for a file or the `-t` option for
plain text. You can also specify the encryption algorithm with the `-a` option.
For example, to hide a file named `msg.txt` inside an image file `image.png`, starting at byte 152000, using the
`Xor` encryption algorithm, you would run:

```bash
./trojanletter -e image.png -k "mykey" -s 152000 -m insert -i ./msg.txt -a Xor
```

This will produce a new file named `<container_file>_loaded` which keeps the original file name and extension but adds
`_loaded` to the end of the name. For example, if the container file was `image.png`, the output file will be
`image_loaded.png`. You can open it to check if it still looks like the original file. The hidden message will be
encrypted and inserted at the specified byte position in the container file. The original file will allways remain
unchanged.

### Extracting a message

To extract a hidden message from a container file, use the `-d` option followed by the container file name, the `-k`
option for the encryption key, and the `-s` option for the starting byte. You
can also specify the encryption algorithm with the `-a` option.
For example, to extract a message from `image_loaded.png`, starting at byte 152000, using the `Xor` encryption
algorithm, you would run:

```bash
./trojanletter -d image_loaded.png -k "mykey" -s 152000 -a Xor
```

Extracting a message will produce a file named `<container_file>_package.txt` in the current directory, which contains
the extracted message. The file will be a txt no matter what the original file was, but the data will remain the same.
This means that if you hid a binary file, the extracted file will still contain the binary data, but it will besaved
as a `.txt` file. You can rename it to the original file extension if needed. If you want to send your recipient an
image for example, you need to inform them what file extension the data is supposed to have. For example by sending a
different container file beforehand with the instructions on how to extract the message in plain text.

---

## Security Considerations

- Always use a strong and unique key for encryption. Making up a long catchphrase is a good idea.
- Do not share details of the encryption through insecure channels. This includes the key, starting byte, and
  encryption algorithm.
- When hiding in files like images, it's better to place the hidden message deep inside the file. This way, the image
  looks more natural and is less likely to be detected by casual inspection. Avoid the first few thousand bytes, as they
  often contain metadata which can easily corrupt the container file if modified. This would make the container file
  very susceptible to detection.
- The tool does not perform any integrity checks on the container file. If the container file is modified or corrupted,
  could return incorrect results or fail to extract the hidden message. This can happen if you choose an image file as a
  container and send it over a platform that compresses images, such as WhatsApp or Discord. Always check the integrity
  of the container file before using it.