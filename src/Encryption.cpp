#ifndef TROJANLETTER_ENCRYPTION_IMPL
#define TROJANLETTER_ENCRYPTION_IMPL
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <ios>
#include <ranges>
#include <vector>

#include "../lib/Encryption.h"

namespace tl {
    std::ifstream Encryption::openInput(const std::string_view path) {
        std::ifstream in(std::string(path), std::ios::binary);
        if (!in) throw std::runtime_error("Failed to open input file: " + std::string(path));
        return in;
    }

    std::ofstream Encryption::openOutput(const std::string_view path) {
        std::ofstream out(std::string(path), std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("Failed to open output file: " + std::string(path));
        return out;
    }

    void Encryption::copyN(std::ifstream &in, std::ofstream &out, std::uint64_t bytesToCopy) {
        std::vector<char> buffer(std::min<std::uint64_t>(kChunkSize, bytesToCopy));
        std::uint64_t remaining = bytesToCopy;
        while (remaining > 0) {
            const std::size_t toRead = static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), remaining));
            in.read(buffer.data(), static_cast<std::streamsize>(toRead));
            const std::streamsize r = in.gcount();
            if (r <= 0) break; // premature EOF
            out.write(buffer.data(), r);
            remaining -= static_cast<std::uint64_t>(r);
        }
    }

    void Encryption::copyRemaining(std::ifstream &in, std::ofstream &out) {
        std::vector<char> buffer(kChunkSize);
        while (in.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || in.gcount() > 0) {
            out.write(buffer.data(), in.gcount());
        }
    }

    void Encryption::xorTransformInPlace(char *data, const std::size_t size, const std::string &key, const bool reverse) {
        if (key.empty()) return; // no-op if empty key — caller should normally validate

        if (!reverse) {
            for (std::size_t i = 0; i < size; ++i)
                for (const char kc: key)
                    data[i] ^= kc;
        } else {
            for (std::size_t i = 0; i < size; ++i)
                for (const char it : std::ranges::reverse_view(key))
                    data[i] ^= it;
        }
    }

    std::vector<char> Encryption::encryptedMarker(const std::string &key) {
        std::vector<char> m(kEndOfDataMarker.begin(), kEndOfDataMarker.end());
        xorTransformInPlace(m.data(), m.size(), key, false);
        return m;
    }

    void Encryption::encryptFile(const std::string_view containerFile, const std::string_view key, const std::uint64_t offset,
                                 const ContainerStuffingMode mode, const MessageData &message) {
        // basic validation
        if (!std::filesystem::exists(std::string(containerFile)))
            throw std::runtime_error("Container does not exist: " + std::string(containerFile));
        if (std::string(key).empty()) throw std::runtime_error("Encryption key cannot be empty");
        if (message.value.empty()) throw std::runtime_error("Message cannot be empty");

        const std::string packaged = std::string(containerFile) + "_packaged";

        if (mode == ContainerStuffingMode::Insert)
            encryptInsert(containerFile, packaged, std::string(key), offset, message);
        else
            encryptOverwrite(containerFile, packaged, std::string(key), offset, message);
    }

    void Encryption::encryptInsert(std::string_view containerFile, std::string_view packagedFile,
                                   const std::string &key,
                                   std::uint64_t offset, const MessageData &message) {
        auto in = openInput(containerFile);
        auto out = openOutput(packagedFile);

        // Get container size and validate
        in.seekg(0, std::ios::end);
        if (std::uint64_t containerSize = in.tellg(); offset > containerSize) throw std::runtime_error("Start offset beyond container size");
        in.seekg(0, std::ios::beg);

        // Copy up to offset
        copyN(in, out, offset);

        // Write message (file or text) encrypted
        if (message.isFilePath) {
            auto msgIn = openInput(message.value);
            std::vector<char> buffer(kChunkSize);
            while (msgIn.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || msgIn.gcount() > 0) {
                auto r = static_cast<std::size_t>(msgIn.gcount());
                xorTransformInPlace(buffer.data(), r, key, false);
                out.write(buffer.data(), static_cast<std::streamsize>(r));
            }
        } else {
            std::vector<char> text(message.value.begin(), message.value.end());
            xorTransformInPlace(text.data(), text.size(), key, false);
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
        }

        // encrypted marker
        auto marker = encryptedMarker(key);
        out.write(marker.data(), static_cast<std::streamsize>(marker.size()));

        // write rest of container
        copyRemaining(in, out);
    }

    void Encryption::encryptOverwrite(std::string_view containerFile, std::string_view packagedFile,
                                      const std::string &key,
                                      std::uint64_t offset, const MessageData &message) {
        auto in = openInput(containerFile);
        auto out = openOutput(packagedFile);

        // Get container size and validate
        in.seekg(0, std::ios::end);
        std::uint64_t containerSize = static_cast<std::uint64_t>(in.tellg());
        if (offset > containerSize) throw std::runtime_error("Start offset beyond container size");
        in.seekg(0, std::ios::beg);

        // Copy up to offset
        copyN(in, out, offset);

        // Overwrite: read from message and either overwrite existing bytes or append if message is larger
        std::uint64_t written = 0;

        auto writeEncryptedChunk = [&](const char *buf, std::size_t len) {
            std::vector<char> tmp(buf, buf + len);
            xorTransformInPlace(tmp.data(), tmp.size(), key, false);
            out.write(tmp.data(), static_cast<std::streamsize>(tmp.size()));
            // advance container read pointer if possible (to consume overwritten bytes)
            if (in) {
                in.read(tmp.data(), static_cast<std::streamsize>(len));
                // ignore what was read — overwritten
            }
            written += len;
        };

        if (message.isFilePath) {
            auto msgIn = openInput(message.value);
            std::vector<char> buffer(kChunkSize);
            while (msgIn.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || msgIn.gcount() > 0) {
                auto r = static_cast<std::size_t>(msgIn.gcount());
                writeEncryptedChunk(buffer.data(), r);
            }
        } else {
            const std::string &txt = message.value;
            const char *p = txt.data();
            std::size_t remaining = txt.size();
            while (remaining > 0) {
                std::size_t part = std::min<std::size_t>(remaining, kChunkSize);
                writeEncryptedChunk(p, part);
                p += part;
                remaining -= part;
            }
        }

        // append encrypted marker
        auto marker = encryptedMarker(key);
        out.write(marker.data(), static_cast<std::streamsize>(marker.size()));

        // if message extended beyond original container, warn
        std::uint64_t endPos = offset + written;
        if (endPos > containerSize) {
            std::cerr << "Warning: message exceeded original container size and extended file.\n";
            // nothing to copy from container because we consumed EOF — but still try to copy any remaining container data (none expected)
            copyRemaining(in, out);
        } else {
            // Copy rest of container starting at (offset + written)
            std::uint64_t toCopy = containerSize - endPos;
            copyN(in, out, toCopy);
        }
    }

    void Encryption::decryptFile(std::string_view containerFile, std::string_view key, std::uint64_t offset,
                                 std::string_view outFile) {
        if (!std::filesystem::exists(std::string(containerFile)))
            throw std::runtime_error("Container does not exist: " + std::string(containerFile));
        if (std::string(key).empty()) throw std::runtime_error("Decryption key cannot be empty");

        const std::string outPath = (outFile.empty()
                                         ? (std::string(containerFile) + "_unpacked.txt")
                                         : std::string(outFile));

        auto in = openInput(containerFile);
        auto out = openOutput(outPath);

        in.seekg(0, std::ios::end);
        std::uint64_t containerSize = static_cast<std::uint64_t>(in.tellg());
        if (offset >= containerSize) throw std::runtime_error("Offset beyond container size");
        in.seekg(static_cast<std::streamoff>(offset), std::ios::beg);

        std::vector<char> buffer(kChunkSize);
        std::vector<char> marker(kEndOfDataMarker.begin(), kEndOfDataMarker.end());
        std::vector<char> encMarker = encryptedMarker(std::string(key));

        // Accumulate all decrypted bytes after offset
        std::vector<char> decrypted;
        bool found = false;

        while (in.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || in.gcount() > 0) {
            auto r = static_cast<std::size_t>(in.gcount());
            xorTransformInPlace(buffer.data(), r, std::string(key), true);

            decrypted.insert(decrypted.end(), buffer.begin(), buffer.begin() + r);

            // Search for marker in decrypted data
            if (decrypted.size() >= marker.size()) {
                auto it = std::search(decrypted.begin(), decrypted.end(), marker.begin(), marker.end());
                if (it != decrypted.end()) {
                    found = true;
                    // Write all bytes before marker
                    out.write(decrypted.data(), std::distance(decrypted.begin(), it));
                    break;
                }
            }
        }

        if (!found) {
            // Marker not found, write all decrypted data
            out.write(decrypted.data(), decrypted.size());
        }

        // done
    }
} // namespace tl

#endif // TROJANLETTER_ENCRYPTION_IMPL
