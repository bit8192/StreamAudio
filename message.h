#pragma once

#include "protocol_magic.h"
#include <vector>
#include <memory>
#include <cstdint>
#include <optional>
#include <openssl/evp.h>

// Forward declarations
namespace Crypto {
    class ED25519;
}

struct Message;

/**
 * 消息体接口
 * 所有消息体类型都应实现此接口
 */
class MessageBody {
public:
    virtual ~MessageBody() = default;
    [[nodiscard]] virtual std::vector<uint8_t> to_byte_array() const = 0;
    [[nodiscard]] virtual size_t size() const = 0;
};

/**
 * 字节数组消息体
 * 最基本的消息体类型，直接封装字节数组
 */
class ByteArrayMessageBody : public MessageBody {
public:
    std::vector<uint8_t> data;

    static constexpr size_t IV_LENGTH = 12;

    ByteArrayMessageBody() = default;
    explicit ByteArrayMessageBody(std::vector<uint8_t> data) : data(std::move(data)) {}
    explicit ByteArrayMessageBody(const uint8_t* ptr, size_t len) : data(ptr, ptr + len) {}

    [[nodiscard]] std::vector<uint8_t> to_byte_array() const override {
        return data;
    }

    [[nodiscard]] size_t size() const override {
        return data.size();
    }

    [[nodiscard]] std::vector<uint8_t> decrypt_aes256gcm(const std::vector<uint8_t>& key) const;

    // 从AES加密数据解密并解析消息
    [[nodiscard]] std::optional<Message> decrypt_aes256gcm_to_msg(const std::vector<uint8_t>& key, const std::shared_ptr<Crypto::ED25519>& verify_sign_key) const;

    // 构建AES加密数据包体
    static ByteArrayMessageBody build_aes256gcm_encrypted_body(
        const std::vector<uint8_t>& plain_data,
        const std::vector<uint8_t>& key
    );
};

// Ed25519公钥消息体
class Ed25519PublicKeyMessageBody : public MessageBody {
public:
    std::vector<uint8_t> public_key;

    explicit Ed25519PublicKeyMessageBody(std::vector<uint8_t> key) : public_key(std::move(key)) {}

    std::vector<uint8_t> to_byte_array() const override {
        return public_key;
    }

    size_t size() const override {
        return public_key.size();
    }
};

// X25519公钥消息体
class X25519PublicKeyMessageBody : public MessageBody {
public:
    std::vector<uint8_t> public_key;

    explicit X25519PublicKeyMessageBody(std::vector<uint8_t> key) : public_key(std::move(key)) {}

    std::vector<uint8_t> to_byte_array() const override {
        return public_key;
    }

    size_t size() const override {
        return public_key.size();
    }
};

// 字符串消息体
class StringMessageBody : public MessageBody {
public:
    std::string message;

    explicit StringMessageBody(std::string msg) : message(std::move(msg)) {}

    std::vector<uint8_t> to_byte_array() const override {
        return std::vector<uint8_t>(message.begin(), message.end());
    }

    size_t size() const override {
        return message.size();
    }
};

/**
 * 消息结构
 * 定义网络通信的消息格式
 */
struct Message {
    ProtocolMagic magic;                          // 协议魔数
    int32_t version;                              // 协议版本
    int32_t queue_num;                            // 队列编号
    int32_t id;                                   // 消息 ID
    int32_t pack_length;                          // 包长度（body 的长度）
    std::shared_ptr<MessageBody> body;            // 消息体
    std::vector<uint8_t> sign;                    // 签名
    uint16_t crc;                                 // CRC16 校验

    // Ed25519 签名长度
    static constexpr size_t SIGNATURE_SIZE = 64;

    // 最小消息长度（不含 body）
    // magic(变长) + version(4) + queue_num(4) + id(4) + pack_length(4) + sign(64) + crc(2)
    static constexpr size_t MIN_LENGTH = 4 + 4 + 4 + 4 + SIGNATURE_SIZE + 2; // 不含 magic

    /**
     * 构建消息（简化构造函数）
     * version 和 crc 会在序列化时自动填充
     */
    static Message build(
        ProtocolMagic magic,
        int32_t queue_num,
        int32_t id,
        std::shared_ptr<MessageBody> body
    );

    /**
     * 从字节流解析消息
     * @param buffer 字节缓冲区
     * @param size 缓冲区大小
     * @param bytes_consumed 输出参数：成功解析时消耗的字节数
     * @param verify_key 用于验证签名的 Ed25519 公钥（可选）
     * @return 解析的消息，失败返回 nullopt
     */
    static std::optional<Message> parse(
        const uint8_t* buffer,
        size_t size,
        size_t& bytes_consumed,
        const std::shared_ptr<Crypto::ED25519>& verify_key
    );

    /**
     * 解析消息体，根据 magic 转换为具体类型
     * @param msg 原始消息（body 为 ByteArrayMessageBody）
     * @return 解析后的消息
     */
    static Message resolve_message(Message msg);

    /**
     * 将消息序列化为字节流（数据部分，不带签名和crc）
     * @return 序列化后的字节数组
     */
    [[nodiscard]] std::vector<uint8_t> serialize_data_section() const;

    /**
     * 将消息序列化为字节流（带签名）
     * @param sign_key 用于签名的 Ed25519 私钥（可选）
     * @return 序列化后的字节数组
     */
    [[nodiscard]] std::vector<uint8_t> serialize(const std::shared_ptr<Crypto::ED25519>& sign_key) const;

    /**
     * 转换为AES-256-GCM加密消息
     * @param sign_key 签名密钥
     * @param encrypt_key 加密密钥
     * @return 加密后的消息
     */
    [[nodiscard]] Message to_aes256gcm_encrypted_message(
        const std::shared_ptr<Crypto::ED25519>& sign_key,
        const std::vector<uint8_t>& encrypt_key
    ) const;

    [[nodiscard]] std::string to_string() const;

    /**
     * 计算消息的 CRC16 校验码
     * @param data 消息数据（不含 CRC 字段）
     * @return CRC16 校验码
     */
    static uint16_t calculate_crc16(const std::vector<uint8_t>& data);

    /**
     * 验证消息签名
     * @param verify_key 用于验证的 Ed25519 公钥
     * @return 签名是否有效
     */
    [[nodiscard]] bool verify_signature(const Crypto::ED25519& verify_key) const;
};
