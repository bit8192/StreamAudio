//
// Created by Bincker on 2025/7/1.
//

#include "crypto.h"

#include <memory>
#include <string>
#include <utility>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

#include "hextool.h"
#include "../exceptions.h"
#include "../logger.h"

constexpr char LOG_TAG[]="Crypto";
constexpr char CRYPTO_NAME_SHA256[] = "SHA256";
const std::vector<uint8_t> derive_key_info = {'s', 't', 'e', 'a', 'm', '-', 'a', 'u', 'd', 'i', '0'};

void handleErrors() {
    BIO *error = BIO_new(BIO_s_mem());
    if (!error) {
        throw CryptoException("Failed to create BIO for error reporting");
    }

    ERR_print_errors(error);

    char *msg = nullptr;
    const long len = BIO_get_mem_data(error, &msg);
    if (len <= 0 || !msg) {
        BIO_free(error);
        throw CryptoException("Failed to get error message");
    }

    try {
        // 确保字符串正确终止
        const std::string errorMsg(msg, len);
        BIO_free(error);
        throw CryptoException(errorMsg);
    } catch (...) {
        BIO_free(error);
        throw;
    }
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

// 使用 EVP_MAC 实现 HMAC 派生密钥
std::vector<uint8_t> hmac_derive_key(
    const std::vector<uint8_t>& shared_secret,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& info) {

    std::vector<uint8_t> derived_key(32); // 假设输出 32 字节（SHA-256）

    // 创建 EVP_MAC 上下文
    EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) {
        throw CryptoException("Error: EVP_MAC_fetch failed");
        return {};
    }

    // 配置 HMAC 参数（算法为 SHA-256）
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char *>(CRYPTO_NAME_SHA256), 0);
    params[1] = OSSL_PARAM_construct_end();

    // 创建 EVP_MAC_CTX
    const std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(EVP_MAC_CTX_new(mac), EVP_MAC_CTX_free);
    if (!ctx) {
        EVP_MAC_free(mac);
        throw CryptoException("Error: EVP_MAC_CTX_new failed");
    }

    // 初始化 HMAC（密钥为 shared_secret）
    if (EVP_MAC_init(ctx.get(), shared_secret.data(), shared_secret.size(), params) != 1) {
        EVP_MAC_free(mac);
        throw CryptoException("Error: EVP_MAC_init failed");
    }

    // 可选：添加盐值（Salt）
    if (!salt.empty() && EVP_MAC_update(ctx.get(), salt.data(), salt.size()) != 1) {
        EVP_MAC_free(mac);
        throw CryptoException("Error: EVP_MAC_update (salt) failed");
    }

    // 添加上下文信息（Info）
    if (!info.empty() && EVP_MAC_update(ctx.get(), info.data(), info.size()) != 1) {
        EVP_MAC_free(mac);
        throw CryptoException("Error: EVP_MAC_update (info) failed");
    }

    // 获取派生密钥
    size_t out_len = derived_key.size();
    if (EVP_MAC_final(ctx.get(), derived_key.data(), &out_len, out_len) != 1) {
        EVP_MAC_free(mac);
        throw CryptoException("Error: EVP_MAC_final failed");
    }

    // 清理资源
    EVP_MAC_free(mac);
    return derived_key;
}

Crypto::KeyPair::KeyPair(std::string name, EVP_PKEY *key, const bool is_public): key(key), is_public(is_public), cache_mutex(std::make_unique<std::mutex>()), name(std::move(name)) {
}

Crypto::ED25519::ED25519(EVP_PKEY *key, const bool is_public): KeyPair("ed25519", key,is_public) {
}

Crypto::X25519::X25519(EVP_PKEY *key, const bool is_public): KeyPair("x25519", key,is_public) {
}

std::shared_ptr<Crypto::ED25519> Crypto::ED25519::generate() {
    return std::shared_ptr<ED25519>(new ED25519(generate_ecc_keypair(NID_ED25519), false));
}

Crypto::X25519 Crypto::X25519::generate() {
    return {generate_ecc_keypair(NID_X25519), false};
}

Crypto::ED25519 Crypto::ED25519::load_public_key_from_file(const std::string &filename) {
    const auto file = fopen(filename.c_str(), "rb");
    if(!file) throw CryptoException("open file failed.");
    const auto pkey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);
    if(!pkey) handleErrors();
    return {pkey, true};
}

Crypto::ED25519 Crypto::ED25519::load_private_key_from_mem(const std::vector<uint8_t>& data)
{
    const auto pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, data.data(), data.size());
    if(!pkey) handleErrors();
    return {pkey, false};
}

Crypto::ED25519 Crypto::ED25519::load_private_key_from_file(const std::string &filename) {
    const auto file = fopen(filename.c_str(), "rb");
    if(!file) throw CryptoException("open file failed.");
    const auto pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    if(!pkey) handleErrors();
    return {pkey, false};
}

Crypto::ED25519 Crypto::ED25519::load_public_key_from_mem(const std::vector<uint8_t> &data) {
    const auto pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, data.data(), data.size());
    if(!pkey) handleErrors();
    return {pkey, true};
}

Crypto::X25519 Crypto::X25519::load_public_key_from_mem(const std::vector<uint8_t> &data) {
    const auto pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, data.data(), data.size());
    if(!pkey) handleErrors();
    return {pkey, true};
}

std::vector<uint8_t> Crypto::KeyPair::export_public_key() const {
    if (!cached_public_key.empty()) return cached_public_key;
    std::lock_guard lock(*cache_mutex);
    if (!cached_public_key.empty()) return cached_public_key;
    size_t len = 32;
    cached_public_key.resize(len);
    EVP_PKEY_get_raw_public_key(key, cached_public_key.data(), &len);
    return cached_public_key;
}

std::vector<uint8_t> Crypto::KeyPair::export_private_key() const {
    if (is_public) throw CryptoException("this is not a private key");
    if (!cached_private_key.empty()) return cached_private_key;
    std::lock_guard lock(*cache_mutex);
    if (!cached_private_key.empty()) return cached_private_key;
    size_t len = 32;
    cached_private_key.resize(len);
    EVP_PKEY_get_raw_private_key(key, cached_private_key.data(), &len);
    return cached_private_key;
}

void Crypto::KeyPair::write_public_key_to_file(const std::string &filename) const {
    FILE* fp = fopen(filename.c_str(), "wb");
    if (!fp) throw CryptoException("Failed to open file");

    if (PEM_write_PUBKEY(fp, key) != 1) {
        fprintf(stderr, "Failed to write PEM\n");
        ERR_print_errors_fp(stderr);
    }

    fclose(fp);
}

void Crypto::KeyPair::write_private_key_to_file(const std::string &filename) const {
    const auto bio = BIO_new_file(filename.c_str(), "wb");
    if (!bio) throw CryptoException("Failed to open file");
    PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(bio);
}

std::string Crypto::KeyPair::get_name() const {
    return name;
}

std::vector<uint8_t> Crypto::ED25519::sign(const std::vector<uint8_t> &data) const {
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

bool Crypto::ED25519::verify(const uint8_t* ptr, const size_t size, const std::vector<uint8_t> &signature) const {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    if (EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, key) <= 0) {
        EVP_MD_CTX_free(mdctx);
        handleErrors();
    }

    const int ret = EVP_DigestVerify(mdctx, signature.data(), signature.size(), ptr, size);
    EVP_MD_CTX_free(mdctx);

    if (ret == 1) return true;
    if (ret == 0) return false;
    handleErrors();
    return false;
}

std::vector<uint8_t> Crypto::X25519::derive_shared_secret(const X25519 &pub_key) const {
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

// 计算 HMAC-SHA256
std::vector<uint8_t> Crypto::hmac_sha256(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data
) {
    std::vector<unsigned char> hmac(EVP_MAX_MD_SIZE);
    size_t hmac_len = 0;

    // 使用 EVP 接口计算 HMAC
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) {
        throw CryptoException("EVP_MAC_fetch failed");
    }

    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        throw CryptoException("EVP_MAC_CTX_new failed");
    }

    // 设置 HMAC 的哈希算法（如 SHA-256）
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char *>(CRYPTO_NAME_SHA256), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(ctx, key.data(), key.size(), params) != 1) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw CryptoException("EVP_MAC_init failed");
    }

    if (EVP_MAC_update(ctx, data.data(), data.size()) != 1) {
        throw CryptoException("EVP_MAC_update failed\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return {};
    }

    if (EVP_MAC_final(ctx, hmac.data(), &hmac_len, hmac.size()) != 1) {
        throw CryptoException("EVP_MAC_final failed\n");
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return {};
    }

    hmac.resize(hmac_len); // 调整大小以匹配实际 HMAC 长度

    // 清理资源
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);

    return hmac;
}

// 计算 SHA-256 哈希
std::vector<uint8_t> Crypto::sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    unsigned int hash_len = 0;

    // 1. 获取 SHA-256 的 EVP_MD 结构
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw CryptoException("EVP_MD_CTX_new failed");
    }

    // 2. 初始化哈希计算（指定 SHA-256）
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw CryptoException("EVP_DigestInit_ex failed");
    }

    // 3. 输入数据
    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw CryptoException("EVP_DigestUpdate failed");
    }

    // 4. 获取哈希结果
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw CryptoException("EVP_DigestFinal_ex failed");
    }

    // 5. 调整输出大小（SHA-256 固定 32 字节）
    hash.resize(hash_len);

    // 6. 释放资源
    EVP_MD_CTX_free(ctx);

    return hash;
}

// AES-256-GCM 加密
std::vector<uint8_t> Crypto::aes_256_gcm_encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext
) {
    if (key.size() != 32) {
        throw CryptoException("AES-256-GCM requires a 32-byte key");
    }
    if (iv.empty()) {
        throw CryptoException("IV cannot be empty");
    }

    Logger::d(LOG_TAG, "encrypt aes256gcm: key={}\tiv={}\tplaintext={}", HEX_TOOL::to_hex(key), HEX_TOOL::to_hex(iv), HEX_TOOL::to_hex(plaintext));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw CryptoException("Failed to create encryption context");
    }

    // 初始化加密
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to initialize AES-256-GCM encryption");
    }

    // 设置 IV 长度
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set IV length");
    }

    // 设置密钥和 IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set key and IV");
    }

    // 加密数据
    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to encrypt data");
    }
    int ciphertext_len = len;

    // 完成加密
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to finalize encryption");
    }
    ciphertext_len += len;

    // 获取 GCM 认证标签（128位 = 16字节）
    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to get authentication tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    // 调整密文大小并附加认证标签
    ciphertext.resize(ciphertext_len);
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

    return ciphertext;
}

// AES-128-GCM 加密
std::vector<uint8_t> Crypto::aes_128_gcm_encrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& plaintext
) {
    if (key.size() != 16) {
        throw CryptoException("AES-128-GCM requires a 16-byte key");
    }
    if (iv.empty()) {
        throw CryptoException("IV cannot be empty");
    }

    Logger::d(LOG_TAG, "encrypt aes128gcm: key={}\tiv={}\tplaintext={}", HEX_TOOL::to_hex(key), HEX_TOOL::to_hex(iv), HEX_TOOL::to_hex(plaintext));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw CryptoException("Failed to create encryption context");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to initialize AES-128-GCM encryption");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set IV length");
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set key and IV");
    }

    std::vector<uint8_t> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to encrypt data");
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to finalize encryption");
    }
    ciphertext_len += len;

    std::vector<uint8_t> tag(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to get authentication tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(ciphertext_len);
    ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

    return ciphertext;
}

// AES-256-GCM 解密
std::vector<uint8_t> Crypto::aes_256_gcm_decrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& ciphertext
) {
    if (key.size() != 32) {
        throw CryptoException("AES-256-GCM requires a 32-byte key");
    }
    if (iv.empty()) {
        throw CryptoException("IV cannot be empty");
    }
    if (ciphertext.size() < 16) {
        throw CryptoException("Ciphertext too short (must include 16-byte authentication tag)");
    }

    Logger::d(LOG_TAG, "decrypt aes256gcm: key={}\tiv={}\tciphertext={}", HEX_TOOL::to_hex(key), HEX_TOOL::to_hex(iv), HEX_TOOL::to_hex(ciphertext));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw CryptoException("Failed to create decryption context");
    }

    // 初始化解密
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to initialize AES-256-GCM decryption");
    }

    // 设置 IV 长度
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set IV length");
    }

    // 设置密钥和 IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set key and IV");
    }

    // 分离密文和认证标签（最后16字节是标签）
    const size_t actual_ciphertext_len = ciphertext.size() - 16;
    std::vector<uint8_t> actual_ciphertext(ciphertext.begin(), ciphertext.begin() + actual_ciphertext_len);
    std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());

    // 解密数据
    std::vector<uint8_t> plaintext(actual_ciphertext_len + EVP_CIPHER_CTX_block_size(ctx));
    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, actual_ciphertext.data(), actual_ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to decrypt data");
    }
    int plaintext_len = len;

    // 设置预期的认证标签
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set authentication tag");
    }

    // 完成解密（会自动验证标签）
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    if (ret <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Decryption failed: authentication tag verification failed");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

// AES-128-GCM 解密
std::vector<uint8_t> Crypto::aes_128_gcm_decrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& ciphertext
) {
    if (key.size() != 16) {
        throw CryptoException("AES-128-GCM requires a 16-byte key");
    }
    if (iv.empty()) {
        throw CryptoException("IV cannot be empty");
    }
    if (ciphertext.size() < 16) {
        throw CryptoException("Ciphertext too short (must include 16-byte authentication tag)");
    }

    Logger::d(LOG_TAG, "decrypt aes128gcm: key={}\tiv={}\tciphertext={}", HEX_TOOL::to_hex(key), HEX_TOOL::to_hex(iv), HEX_TOOL::to_hex(ciphertext));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw CryptoException("Failed to create decryption context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to initialize AES-128-GCM decryption");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set IV length");
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set key and IV");
    }

    const size_t actual_ciphertext_len = ciphertext.size() - 16;
    std::vector<uint8_t> actual_ciphertext(ciphertext.begin(), ciphertext.begin() + actual_ciphertext_len);
    std::vector<uint8_t> tag(ciphertext.end() - 16, ciphertext.end());

    std::vector<uint8_t> plaintext(actual_ciphertext_len + EVP_CIPHER_CTX_block_size(ctx));
    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, actual_ciphertext.data(), actual_ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to decrypt data");
    }
    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Failed to set authentication tag");
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    if (ret <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoException("Decryption failed: authentication tag verification failed");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}
