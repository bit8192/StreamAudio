//
// Created by Bincker on 2025/7/1.
//

#include "crypto.h"

#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "../exceptions.h"

void handleErrors() {
    const auto error = BIO_new(BIO_s_mem());
    ERR_print_errors(error);
    long len = BIO_get_mem_data(error, nullptr);
    char msg[len + 1];
    BIO_get_mem_data(error, msg);
    throw CryptoException(msg);
}

EVP_PKEY * generate_ecc_keypair(const int id) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(id, nullptr);
    if (!pctx) handleErrors();

    if (EVP_PKEY_keygen_init(pctx) <= 0) handleErrors();

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) handleErrors();

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

KeyPair::KeyPair(EVP_PKEY *key, const bool is_public): key(key), is_public(is_public) {
}

ED25519::ED25519(EVP_PKEY *key, const bool is_public): KeyPair(key,is_public) {
}

X25519::X25519(EVP_PKEY *key, const bool is_public): KeyPair(key,is_public) {
}

ED25519 ED25519::empty() {
    return {nullptr, false};
}

ED25519 ED25519::generate() {
    return {generate_ecc_keypair(NID_ED25519), false};
}

X25519 X25519::generate() {
    return {generate_ecc_keypair(NID_X25519), false};
}

ED25519 ED25519::load_public_key_from_file(const std::string &filename) {
    const auto file = fopen(filename.c_str(), "rb");
    if(!file) throw CryptoException("open file failed.");
    const auto pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);
    if(!pkey) handleErrors();
    return {pkey, true};
}

ED25519 ED25519::load_private_key_from_file(const std::string &filename) {
    const auto file = fopen(filename.c_str(), "rb");
    if(!file) throw CryptoException("open file failed.");
    const auto pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    if(!pkey) handleErrors();
    return {pkey, false};
}

ED25519 ED25519::load_public_key_from_mem(const std::vector<uint8_t> &data) {
    const auto pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, data.data(), data.size());
    if(!pkey) handleErrors();
    return {pkey, true};
}

X25519 X25519::load_public_key_from_mem(const std::vector<uint8_t> &data) {
    const auto pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, data.data(), data.size());
    if(!pkey) handleErrors();
    return {pkey, true};
}

std::vector<uint8_t> KeyPair::export_public_key() const {
    if (!is_public) throw CryptoException("this is not a public key");
    size_t len = 32;
    std::vector<uint8_t> pubkey(len, 0);
    EVP_PKEY_get_raw_public_key(key, pubkey.data(), &len);
    return pubkey;
}

std::vector<uint8_t> KeyPair::export_private_key() const {
    if (is_public) throw CryptoException("this is not a private key");
    size_t len = 32;
    std::vector<uint8_t> prev_key(len, 0);
    EVP_PKEY_get_raw_private_key(key, prev_key.data(), &len);
    return prev_key;
}

void KeyPair::write_public_key_to_file(const std::string &filename) const {
    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp) throw CryptoException("Failed to open file");

    if (PEM_write_PUBKEY(fp, key) != 1) {
        fprintf(stderr, "Failed to write PEM\n");
        ERR_print_errors_fp(stderr);
    }

    fclose(fp);
}

void KeyPair::write_private_key_to_file(const std::string &filename) const {
    const auto bio = BIO_new_file(filename.c_str(), "wb");
    if (!bio) throw CryptoException("Failed to open file");
    PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(bio);
}

std::vector<uint8_t> ED25519::sign(const std::vector<uint8_t> &data) const {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, key) <= 0) {
        EVP_MD_CTX_free(mdctx);
        handleErrors();
    }

    size_t siglen;
    if (EVP_DigestSign(mdctx, nullptr, &siglen, data.data(), data.size()) <= 0) {
        EVP_MD_CTX_free(mdctx);
        handleErrors();
    }

    std::vector<uint8_t> signature(siglen);
    if (EVP_DigestSign(mdctx, signature.data(), &siglen, data.data(), data.size()) <= 0) {
        EVP_MD_CTX_free(mdctx);
        handleErrors();
    }

    EVP_MD_CTX_free(mdctx);
    return signature;
}

bool ED25519::verify(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature) const {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, key) <= 0) {
        EVP_MD_CTX_free(mdctx);
        handleErrors();
    }

    const int ret = EVP_DigestVerify(mdctx, signature.data(), signature.size(), data.data(), data.size());
    EVP_MD_CTX_free(mdctx);

    if (ret == 1) return true;
    if (ret == 0) return false;
    handleErrors();
    return false;
}

std::vector<uint8_t> X25519::derive_shared_secret(const X25519 &pub_key) const {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
    if (!ctx) handleErrors();

    if (EVP_PKEY_derive_init(ctx) <= 0) handleErrors();

    if (EVP_PKEY_derive_set_peer(ctx, pub_key.key) <= 0) handleErrors();

    size_t secret_len;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) handleErrors();

    std::vector<uint8_t> shared_secret(secret_len);
    if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return shared_secret;
}
