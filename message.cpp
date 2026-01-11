#include "message.h"
#include "logger.h"
#include <stdexcept>
#include <cstring>

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
        uint16_t crc = static_cast<uint16_t>(i << 8);
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
    ProtocolMagic magic,
    int32_t queue_num,
    int32_t id,
    std::shared_ptr<MessageBody> body
) {
    Message msg;
    msg.magic = magic;
    msg.version = 1; // TODO: 从配置获取版本号
    msg.queue_num = queue_num;
    msg.id = id;
    msg.body = std::move(body);
    msg.pack_length = msg.body ? static_cast<int32_t>(msg.body->size()) : 0;
    msg.crc = 0; // 序列化时计算

    return msg;
}

// 序列化消息
std::vector<uint8_t> Message::serialize() const {
    auto magic_bytes = to_bytes(magic);
    std::vector<uint8_t> buffer;
    buffer.reserve(magic_bytes.size() + 4 + 4 + 4 + 4 + pack_length + 2);

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

    // 计算并写入 CRC（不含 CRC 字段本身）
    uint16_t crc_value = calculate_crc16(buffer);
    write_uint16_be(buffer, crc_value);

    return buffer;
}

// 解析消息
std::optional<Message> Message::parse(
    const uint8_t* buffer,
    size_t size,
    size_t& bytes_consumed
) {
    // 检查最小长度
    size_t min_magic_len = ProtocolMagicHelper::min_magic_length();
    if (size < min_magic_len + MIN_LENGTH) {
        return std::nullopt;
    }

    // 匹配魔数
    size_t magic_end_offset = 0;
    auto magic_opt = ProtocolMagicHelper::match(buffer, size, magic_end_offset);
    if (!magic_opt) {
        return std::nullopt;
    }

    // 检查剩余数据是否足够
    if (size - magic_end_offset < MIN_LENGTH) {
        return std::nullopt;
    }

    const uint8_t* ptr = buffer + magic_end_offset;

    // 读取 header（大端序）
    int32_t version = read_int32_be(ptr);
    ptr += 4;

    int32_t queue_num = read_int32_be(ptr);
    ptr += 4;

    int32_t id = read_int32_be(ptr);
    ptr += 4;

    int32_t pack_length = read_int32_be(ptr);
    ptr += 4;

    // 检查是否有足够的数据（body + CRC）
    size_t remaining = size - (ptr - buffer);
    if (remaining < static_cast<size_t>(pack_length + 2)) {
        return std::nullopt;
    }

    // 读取 body
    std::vector<uint8_t> body_data;
    if (pack_length > 0) {
        body_data.assign(ptr, ptr + pack_length);
        ptr += pack_length;
    }

    // 读取 CRC
    uint16_t received_crc = read_uint16_be(ptr);
    ptr += 2;

    // 验证 CRC（不含 CRC 字段）
    size_t message_len = ptr - buffer - 2; // 不含 CRC
    std::vector<uint8_t> crc_data(buffer, buffer + message_len);
    uint16_t calculated_crc = calculate_crc16(crc_data);

    if (received_crc != calculated_crc) {
        Logger::w("Message", "CRC mismatch: received=" + std::to_string(received_crc) +
                             " calculated=" + std::to_string(calculated_crc));
        // 注意：这里可以选择返回错误或继续处理
        // return std::nullopt;
    }

    // 构建消息对象
    Message msg;
    msg.magic = *magic_opt;
    msg.version = version;
    msg.queue_num = queue_num;
    msg.id = id;
    msg.pack_length = pack_length;
    msg.body = std::make_shared<ByteArrayMessageBody>(body_data);
    msg.crc = received_crc;

    // 设置消耗的字节数
    bytes_consumed = ptr - buffer;

    return msg;
}
