//
// Crypto module tests
//

#include "../test_utils.h"
#include "../tools/crypto.h"
#include "../exceptions.h"
#include <vector>
#include <string>

// 测试 SHA256 哈希
TEST(sha256_basic) {
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    auto hash = Crypto::sha256(data);

    ASSERT_EQ(hash.size(), 32);  // SHA256 总是 32 字节

    // 验证 "hello" 的 SHA256 哈希值
    std::string expected_hex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    ASSERT_EQ(TestUtils::to_hex(hash), expected_hex);
}

// 测试 AES-256-GCM 加密基本功能
TEST(aes_gcm_encrypt_decrypt_basic) {
    const std::string plaintext_str = "hello";
    std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());

    // 生成密钥和 IV
    std::vector<uint8_t> key_input = {'k', 'e', 'y'};
    std::vector<uint8_t> key = Crypto::sha256(key_input);  // 32 字节密钥
    std::vector<uint8_t> iv = {'i', 'v'};

    // 加密
    auto ciphertext = Crypto::aes_256_gcm_encrypt(key, iv, plaintext);

    // 验证密文长度（明文 + 16 字节认证标签）
    ASSERT_EQ(ciphertext.size(), plaintext.size() + 16);

    // 解密
    auto decrypted = Crypto::aes_256_gcm_decrypt(key, iv, ciphertext);

    // 验证解密结果
    ASSERT_EQ(decrypted.size(), plaintext.size());
    ASSERT_TRUE(TestUtils::bytes_equal(decrypted, plaintext));
}

// 测试与 Kotlin 测试的兼容性
TEST(aes_gcm_kotlin_compatibility) {
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> iv = {'i', 'v'};
    std::vector<uint8_t> key_input = {'k', 'e', 'y'};
    auto key = Crypto::sha256(key_input);

    // 加密
    auto encrypted = Crypto::aes_256_gcm_encrypt(key, iv, data);

    // 验证加密结果与 Kotlin 测试一致
    std::string expected_hex = "9b4c7259d263bd0196472a927688ff1ef42e2106e8";
    ASSERT_EQ(TestUtils::to_hex(encrypted), expected_hex);

    // 解密
    auto decrypted = Crypto::aes_256_gcm_decrypt(key, iv, encrypted);
    ASSERT_TRUE(TestUtils::bytes_equal(decrypted, data));
}

// 测试使用错误密钥解密
TEST(aes_gcm_wrong_key) {
    std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> iv = {'i', 'v'};

    auto key1 = Crypto::sha256(std::vector<uint8_t>{'k', 'e', 'y', '1'});
    auto key2 = Crypto::sha256(std::vector<uint8_t>{'k', 'e', 'y', '2'});

    // 用 key1 加密
    auto ciphertext = Crypto::aes_256_gcm_encrypt(key1, iv, plaintext);

    // 用 key2 解密应该失败
    ASSERT_THROW(
        Crypto::aes_256_gcm_decrypt(key2, iv, ciphertext),
        CryptoException
    );
}

// 测试密文被篡改的情况
TEST(aes_gcm_tampered_ciphertext) {
    std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> iv = {'i', 'v'};
    auto key = Crypto::sha256(std::vector<uint8_t>{'k', 'e', 'y'});

    // 加密
    auto ciphertext = Crypto::aes_256_gcm_encrypt(key, iv, plaintext);

    // 篡改密文的第一个字节
    ciphertext[0] ^= 0x01;

    // 解密应该失败（认证标签验证失败）
    ASSERT_THROW(
        Crypto::aes_256_gcm_decrypt(key, iv, ciphertext),
        CryptoException
    );
}

// 测试空数据加密
TEST(aes_gcm_empty_data) {
    std::vector<uint8_t> plaintext;  // 空数据
    std::vector<uint8_t> iv = {'i', 'v'};
    auto key = Crypto::sha256(std::vector<uint8_t>{'k', 'e', 'y'});

    // 加密空数据
    auto ciphertext = Crypto::aes_256_gcm_encrypt(key, iv, plaintext);

    // 应该只包含认证标签（16 字节）
    ASSERT_EQ(ciphertext.size(), 16);

    // 解密
    auto decrypted = Crypto::aes_256_gcm_decrypt(key, iv, ciphertext);
    ASSERT_EQ(decrypted.size(), 0);
}

// 测试较大数据
TEST(aes_gcm_large_data) {
    // 创建 1KB 的测试数据
    std::vector<uint8_t> plaintext(1024);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>(i % 256);
    }

    std::vector<uint8_t> iv(12, 0);  // 12 字节 IV（推荐长度）
    auto key = Crypto::sha256(std::vector<uint8_t>{'k', 'e', 'y'});

    // 加密
    auto ciphertext = Crypto::aes_256_gcm_encrypt(key, iv, plaintext);
    ASSERT_EQ(ciphertext.size(), plaintext.size() + 16);

    // 解密
    auto decrypted = Crypto::aes_256_gcm_decrypt(key, iv, ciphertext);
    ASSERT_TRUE(TestUtils::bytes_equal(decrypted, plaintext));
}

// 测试无效密钥长度
TEST(aes_gcm_invalid_key_length) {
    std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> iv = {'i', 'v'};
    std::vector<uint8_t> wrong_key(16);  // 16 字节密钥，应该是 32 字节

    // 应该抛出异常
    ASSERT_THROW(
        Crypto::aes_256_gcm_encrypt(wrong_key, iv, plaintext),
        CryptoException
    );
}

// 测试空 IV
TEST(aes_gcm_empty_iv) {
    std::vector<uint8_t> plaintext = {'h', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> iv;  // 空 IV
    auto key = Crypto::sha256(std::vector<uint8_t>{'k', 'e', 'y'});

    // 应该抛出异常
    ASSERT_THROW(
        Crypto::aes_256_gcm_encrypt(key, iv, plaintext),
        CryptoException
    );
}

// 测试 HMAC-SHA256
TEST(hmac_sha256_basic) {
    std::vector<uint8_t> key = {'k', 'e', 'y'};
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};

    auto hmac = Crypto::hmac_sha256(key, data);

    // HMAC-SHA256 输出应该是 32 字节
    ASSERT_EQ(hmac.size(), 32);

    // 相同的输入应该产生相同的输出
    auto hmac2 = Crypto::hmac_sha256(key, data);
    ASSERT_TRUE(TestUtils::bytes_equal(hmac, hmac2));
}

// 测试 ECDH 密钥交换
TEST(x25519_key_exchange) {
    // 生成两个密钥对
    auto alice = Crypto::X25519::generate();
    auto bob = Crypto::X25519::generate();

    // 导出公钥
    auto alice_pub = alice.export_public_key();
    auto bob_pub = bob.export_public_key();

    // X25519 公钥应该是 32 字节
    ASSERT_EQ(alice_pub.size(), 32);
    ASSERT_EQ(bob_pub.size(), 32);

    // 从内存加载对方的公钥
    auto alice_pub_loaded = Crypto::X25519::load_public_key_from_mem(alice_pub);
    auto bob_pub_loaded = Crypto::X25519::load_public_key_from_mem(bob_pub);

    // 派生共享密钥
    auto secret1 = alice.derive_shared_secret(bob_pub_loaded);
    auto secret2 = bob.derive_shared_secret(alice_pub_loaded);

    // 双方应该得到相同的共享密钥
    ASSERT_TRUE(TestUtils::bytes_equal(secret1, secret2));
    ASSERT_EQ(secret1.size(), 32);  // 派生密钥应该是 32 字节
}

// 测试 ED25519 签名和验证
TEST(ed25519_sign_verify) {
    // 生成密钥对
    auto keypair = Crypto::ED25519::generate();

    // 测试数据
    std::vector<uint8_t> data = {'h', 'e', 'l', 'l', 'o'};

    // 签名
    auto signature = keypair->sign(data);

    // ED25519 签名应该是 64 字节
    ASSERT_EQ(signature.size(), 64);

    // 验证签名
    bool valid = keypair->verify(data.data(), data.size(), signature);
    ASSERT_TRUE(valid);

    // 修改数据后验证应该失败
    std::vector<uint8_t> tampered_data = {'h', 'e', 'l', 'l', 'O'};
    bool invalid = keypair->verify(tampered_data.data(), tampered_data.size(), signature);
    ASSERT_FALSE(invalid);
}
