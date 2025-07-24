//
// Created by Bincker on 2025/7/1.
//

#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <openssl/types.h>

namespace Crypto {
    class KeyPair {
    protected:
        EVP_PKEY *key = nullptr;
        bool is_public = false;
    private:
        std::string name;

    public:
        explicit KeyPair(std::string name, EVP_PKEY *key, bool is_public);

        [[nodiscard]] std::vector<uint8_t> export_public_key() const;

        [[nodiscard]] std::vector<uint8_t> export_private_key() const;

        void write_public_key_to_file(const std::string &filename) const;

        void write_private_key_to_file(const std::string &filename) const;

        [[nodiscard]] std::string get_name() const;
    };

    class ED25519 : public KeyPair {
        ED25519(EVP_PKEY *key, bool is_public);

    public:
        static ED25519 empty();

        static ED25519 generate();

        static ED25519 load_public_key_from_file(const std::string &filename);

        static ED25519 load_private_key_from_file(const std::string &filename);

        static ED25519 load_public_key_from_mem(const std::vector<uint8_t> &data);

        [[nodiscard]] std::vector<uint8_t> sign(const std::vector<uint8_t> &data) const;

        [[nodiscard]] bool verify(const uint8_t* ptr, const size_t size, const std::vector<uint8_t> &signature) const;
    };

    class X25519 : public KeyPair {
        X25519(EVP_PKEY *key, bool is_public);

    public:
        static X25519 generate();

        static X25519 load_public_key_from_mem(const std::vector<uint8_t> &data);

        [[nodiscard]] std::vector<uint8_t> derive_shared_secret(const X25519 &pub_key,
                                                                const std::vector<uint8_t> &salt) const;
    };

    std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data);
    std::vector<uint8_t> sha256(const std::vector<uint8_t> &data);
}

#endif //CRYPTO_H
