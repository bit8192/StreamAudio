//
// Created by Bincker on 2025/7/1.
//

#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <vector>
#include <openssl/types.h>

class KeyPair {
public:
    explicit KeyPair(EVP_PKEY *key, bool is_public);
protected:
    EVP_PKEY *key = nullptr;
    bool is_public = false;
public:
    [[nodiscard]] std::vector<unsigned char> export_public_key() const;
    [[nodiscard]] std::vector<unsigned char> export_private_key() const;
    void write_public_key_to_file(const std::string& filename) const;
    void write_private_key_to_file(const std::string& filename) const;
};

class ED25519: public KeyPair {
    ED25519(EVP_PKEY *key, bool is_public);
public:
    static ED25519 empty();
    static ED25519 generate();
    static ED25519 load_public_key_from_file(const std::string& filename);
    static ED25519 load_private_key_from_file(const std::string& filename);
    static ED25519 load_public_key_from_mem(const std::vector<unsigned char>& data);
    [[nodiscard]] std::vector<unsigned char> sign(const std::vector<unsigned char>& data) const;
    [[nodiscard]] bool verify(const std::vector<unsigned char>& data, const std::vector<unsigned char>& signature) const;
};

class X25519: public KeyPair {
    X25519(EVP_PKEY *key, bool is_public);
public:
    static X25519 generate();
    static X25519 load_public_key_from_mem(const std::vector<unsigned char>& data);
    [[nodiscard]] std::vector<unsigned char> derive_shared_secret(const X25519& pub_key) const;
};

#endif //CRYPTO_H
