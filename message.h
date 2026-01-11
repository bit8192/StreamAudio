#pragma once

#include "protocol_magic.h"
#include <vector>
#include <memory>
#include <cstdint>

/**
 * 消息体接口
 * 所有消息体类型都应实现此接口
 */
class MessageBody {
public:
    virtual ~MessageBody() = default;
    virtual std::vector<uint8_t> to_byte_array() const = 0;
    virtual size_t size() const = 0;
};

/**
 * 字节数组消息体
 * 最基本的消息体类型，直接封装字节数组
 */
class ByteArrayMessageBody : public MessageBody {
public:
    std::vector<uint8_t> data;

    ByteArrayMessageBody() = default;
    explicit ByteArrayMessageBody(std::vector<uint8_t> data) : data(std::move(data)) {}
    explicit ByteArrayMessageBody(const uint8_t* ptr, size_t len) : data(ptr, ptr + len) {}

    std::vector<uint8_t> to_byte_array() const override {
        return data;
    }

    size_t size() const override {
        return data.size();
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
    uint16_t crc;                                 // CRC16 校验

    // 最小消息长度（不含 body）
    // magic(变长) + version(4) + queue_num(4) + id(4) + pack_length(4) + crc(2)
    static constexpr size_t MIN_LENGTH = 4 + 4 + 4 + 4 + 2; // 不含 magic

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
     * @return 解析的消息，失败返回 nullopt
     */
    static std::optional<Message> parse(
        const uint8_t* buffer,
        size_t size,
        size_t& bytes_consumed
    );

    /**
     * 将消息序列化为字节流
     * @return 序列化后的字节数组
     */
    std::vector<uint8_t> serialize() const;

    /**
     * 计算消息的 CRC16 校验码
     * @param data 消息数据（不含 CRC 字段）
     * @return CRC16 校验码
     */
    static uint16_t calculate_crc16(const std::vector<uint8_t>& data);
};
