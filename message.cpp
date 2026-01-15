#include "message.h"
#include "logger.h"
#include "exceptions.h"
#include <version.h>
#include "tools/hextool.h"
#include "tools/crypto.h"
#include <random>

// CRC16-CCITT 多项式和初始值
static constexpr uint16_t CRC_POLYNOMIAL = 0x1021;
static constexpr uint16_t CRC_INITIAL_VALUE = 0xFFFF;

// 预计算的 CRC16 查找表
static uint16_t crc_table[256];
static bool crc_table_initialized = false;

// 初始化 CRC16 查找表
static void init_crc_table() {
    if (crc_table_initialized) return;

    for (int i = 0; i < 256; ++i) {
        auto crc = static_cast<uint16_t>(i << 8);
        for (int j = 0; j < 8; ++j) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ CRC_POLYNOMIAL;
            } else {
                crc = crc << 1;
            }
        }
        crc_table[i] = crc;
    }

    crc_table_initialized = true;
}

// 计算 CRC16
uint16_t Message::calculate_crc16(const std::vector<uint8_t>& data) {
    init_crc_table();

    uint16_t crc = CRC_INITIAL_VALUE;
    for (uint8_t byte : data) {
        uint8_t index = ((crc >> 8) ^ byte) & 0xFF;
        crc = ((crc << 8) ^ crc_table[index]) & 0xFFFF;
    }

    return crc;
}

bool Message::verify_signature(const Crypto::ED25519& verify_key) const
{
    const auto data = serialize_data_section();
    return verify_key.verify(data.data(), ProtocolMagicHelper::get_magic_bytes_len(magic) + MIN_LENGTH + pack_length, sign);
}

// 辅助函数：写入 32 位整数（大端序）
static void write_int32_be(std::vector<uint8_t>& buffer, int32_t value) {
    buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

// 辅助函数：读取 32 位整数（大端序）
static int32_t read_int32_be(const uint8_t* buffer) {
    return (static_cast<int32_t>(buffer[0]) << 24) |
           (static_cast<int32_t>(buffer[1]) << 16) |
           (static_cast<int32_t>(buffer[2]) << 8) |
           static_cast<int32_t>(buffer[3]);
}

// 辅助函数：写入 16 位整数（大端序）
static void write_uint16_be(std::vector<uint8_t>& buffer, uint16_t value) {
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

// 辅助函数：读取 16 位整数（大端序）
static uint16_t read_uint16_be(const uint8_t* buffer) {
    return (static_cast<uint16_t>(buffer[0]) << 8) |
           static_cast<uint16_t>(buffer[1]);
}

// 构建消息
Message Message::build(
    const ProtocolMagic magic,
    const int32_t queue_num,
    const int32_t id,
    std::shared_ptr<MessageBody> body
) {
    Message msg;
    msg.magic = magic;
    msg.version = VERSION_CODE;
    msg.queue_num = queue_num;
    msg.id = id;
    msg.body = std::move(body);
    msg.pack_length = msg.body ? static_cast<int32_t>(msg.body->size()) : 0;
    msg.crc = 0; // 序列化时计算
    return msg;
}

std::vector<uint8_t> Message::serialize_data_section() const
{
    auto magic_bytes = to_bytes(magic);
    std::vector<uint8_t> buffer;
    buffer.reserve(magic_bytes.size() + pack_length + MIN_LENGTH);

    // 写入魔数
    buffer.insert(buffer.end(), magic_bytes.begin(), magic_bytes.end());

    // 写入 header（大端序）
    write_int32_be(buffer, version);
    write_int32_be(buffer, queue_num);
    write_int32_be(buffer, id);
    write_int32_be(buffer, pack_length);

    // 写入 body
    if (body && pack_length > 0) {
        auto body_data = body->to_byte_array();
        buffer.insert(buffer.end(), body_data.begin(), body_data.end());
    }
    return buffer;
}

// 序列化消息
std::vector<uint8_t> Message::serialize(const std::shared_ptr<Crypto::ED25519>& sign_key) const {
    auto buffer = serialize_data_section();
    // 写入签名
    if (sign_key) {
        auto signature = sign_key->sign(buffer);
        buffer.insert(buffer.end(), signature.begin(), signature.end());
    } else {
        // 无签名时填充空字节
        buffer.insert(buffer.end(), SIGNATURE_SIZE, 0);
    }

    // 计算并写入 CRC（不含 CRC 字段本身）
    uint16_t crc_value = calculate_crc16(buffer);
    write_uint16_be(buffer, crc_value);

    return buffer;
}

std::string Message::to_string() const {
    return std::format(
        "Message(magic={},version={},queue_num={},id={},pack_length={},body={},sign={},crc={})",
        ProtocolMagicHelper::get_magic_string(magic),
        version,
        queue_num,
        id,
        pack_length,
        HEX_TOOL::to_hex(body->to_byte_array().data(), body->to_byte_array().size()),
        HEX_TOOL::to_hex(sign.data(), sign.size()),
        crc
    );
}

// 解析消息
std::optional<Message> Message::parse(
    const uint8_t* buffer,
    const size_t size,
    size_t& bytes_consumed,
    const std::shared_ptr<Crypto::ED25519>& verify_key
) {
    // 检查最小长度
    if (size < MIN_MAGIC_LENGTH + MIN_LENGTH) {
        return std::nullopt;
    }

    // 匹配魔数
    size_t magic_end_offset = 0;
    const auto magic_opt = ProtocolMagicHelper::match(buffer, size, magic_end_offset);
    if (!magic_opt) {
        return std::nullopt;
    }

    // 检查剩余数据是否足够
    if (size - magic_end_offset < MIN_LENGTH) {
        return std::nullopt;
    }

    const uint8_t* ptr = buffer + magic_end_offset;

    // 读取 header（大端序）
    const int32_t version = read_int32_be(ptr);
    ptr += 4;

    const int32_t queue_num = read_int32_be(ptr);
    ptr += 4;

    const int32_t id = read_int32_be(ptr);
    ptr += 4;

    const int32_t pack_length = read_int32_be(ptr);
    ptr += 4;

    // 检查是否有足够的数据（body + sign + CRC）
    if (const size_t remaining = size - (ptr - buffer); remaining < pack_length + SIGNATURE_SIZE + 2) {
        return std::nullopt;
    }

    // 读取 body
    std::vector<uint8_t> body_data;
    if (pack_length > 0) {
        body_data.assign(ptr, ptr + pack_length);
        ptr += pack_length;
    }

    // 读取签名
    const std::vector signature(ptr, ptr + SIGNATURE_SIZE);
    ptr += SIGNATURE_SIZE;

    // 验证签名（如果提供了验证密钥）
    if (verify_key) {
        const size_t sign_data_len = ptr - buffer - SIGNATURE_SIZE;
        if (!verify_key->verify(buffer, sign_data_len, signature)) {
            Logger::w("Message", "Signature verification failed");
            return std::nullopt;
        }
    }

    // 读取 CRC
    const uint16_t received_crc = read_uint16_be(ptr);
    ptr += 2;

    // 验证 CRC（不含 CRC 字段）
    const size_t message_len = ptr - buffer - 2; // 不含 CRC
    const std::vector crc_data(buffer, buffer + message_len);
    uint16_t calculated_crc = calculate_crc16(crc_data);

    if (received_crc != calculated_crc) {
        Logger::w("Message", "CRC mismatch: received=" + std::to_string(received_crc) +
                             " calculated=" + std::to_string(calculated_crc));
        return std::nullopt;
    }

    // 构建消息对象
    Message msg;
    msg.magic = *magic_opt;
    msg.version = version;
    msg.queue_num = queue_num;
    msg.id = id;
    msg.pack_length = pack_length;
    msg.body = std::make_shared<ByteArrayMessageBody>(body_data);
    msg.sign = signature;
    msg.crc = received_crc;

    // 设置消耗的字节数
    bytes_consumed = ptr - buffer;

    return resolve_message(std::move(msg));
}

// ByteArrayMessageBody 加密解密方法
std::optional<Message> ByteArrayMessageBody::decrypt_aes256gcm(const std::vector<uint8_t>& key, const std::shared_ptr<Crypto::ED25519>& verify_sign_key) const {
    if (data.size() < IV_LENGTH) {
        Logger::w("ByteArrayMessageBody", "Encrypted data too short");
        return std::nullopt;
    }

    // 提取 IV 和密文
    const std::vector iv(data.begin(), data.begin() + IV_LENGTH);
    const std::vector ciphertext(data.begin() + IV_LENGTH, data.end());

    try {
        // 解密
        const auto plaintext = Crypto::aes_256_gcm_decrypt(key, iv, ciphertext);

        // 解析解密后的消息
        size_t bytes_consumed = 0;
        return Message::parse(plaintext.data(), plaintext.size(), bytes_consumed, verify_sign_key);
    } catch (const std::exception& e) {
        Logger::e("ByteArrayMessageBody", std::string("Decryption failed"), e);
        return std::nullopt;
    }
}

ByteArrayMessageBody ByteArrayMessageBody::build_aes256gcm_encrypted_body(
    const std::vector<uint8_t>& plain_data,
    const std::vector<uint8_t>& key
) {
    // 生成随机 IV
    std::vector<uint8_t> iv(IV_LENGTH);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : iv) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    // 加密
    auto ciphertext = Crypto::aes_256_gcm_encrypt(key, iv, plain_data);

    // 组合 IV + 密文
    std::vector<uint8_t> encrypted_data;
    encrypted_data.reserve(IV_LENGTH + ciphertext.size());
    encrypted_data.insert(encrypted_data.end(), iv.begin(), iv.end());
    encrypted_data.insert(encrypted_data.end(), ciphertext.begin(), ciphertext.end());

    return ByteArrayMessageBody(encrypted_data);
}

// 转换为加密消息
Message Message::to_aes256gcm_encrypted_message(
    const std::shared_ptr<Crypto::ED25519>& sign_key,
    const std::vector<uint8_t>& encrypt_key
) const {
    // 先序列化并签名原始消息
    const auto serialized = serialize(sign_key);

    // 加密序列化后的数据
    auto encrypted_body = ByteArrayMessageBody::build_aes256gcm_encrypted_body(serialized, encrypt_key);

    // 构建加密消息
    Message encrypted_msg;
    encrypted_msg.magic = ProtocolMagic::ENCRYPTED;
    encrypted_msg.version = this->version;
    encrypted_msg.queue_num = this->queue_num;
    encrypted_msg.id = this->id;
    encrypted_msg.pack_length = static_cast<int32_t>(encrypted_body.size());
    encrypted_msg.body = std::make_shared<ByteArrayMessageBody>(encrypted_body);
    encrypted_msg.sign = std::vector<uint8_t>(SIGNATURE_SIZE, 0); // 加密消息不签名
    encrypted_msg.crc = 0; // 序列化时计算

    return encrypted_msg;
}

// 消息解析：根据 magic 转换为具体类型
Message Message::resolve_message(Message msg) {
    const auto byte_body = std::dynamic_pointer_cast<ByteArrayMessageBody>(msg.body);
    if (!byte_body) {
        return msg;
    }

    switch (msg.magic) {
    case ProtocolMagic::PAIR:
    case ProtocolMagic::PAIR_RESPONSE:
    case ProtocolMagic::ECDH:
    case ProtocolMagic::ECDH_RESPONSE:
    case ProtocolMagic::AUTHENTICATION:
    case ProtocolMagic::AUTHENTICATION_RESPONSE:
    case ProtocolMagic::PLAY:
    case ProtocolMagic::PLAY_RESPONSE:
    case ProtocolMagic::STOP:
    case ProtocolMagic::STOP_RESPONSE:
    case ProtocolMagic::ENCRYPTED:
        // 保持为 ByteArrayMessageBody
        break;
    case ProtocolMagic::ERROR:
        // 字符串消息
        msg.body = std::make_shared<StringMessageBody>(
            std::string(byte_body->data.begin(), byte_body->data.end())
        );
        break;
    }

    return msg;
}
