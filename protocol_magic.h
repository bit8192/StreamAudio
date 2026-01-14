#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <algorithm>
#include <optional>
#include <cstdint>

/**
 * 协议魔数枚举
 * 用于标识不同类型的网络消息
 */
enum class ProtocolMagic {
    ECDH,
    ECDH_RESPONSE,
    PAIR,
    PAIR_RESPONSE,
    AUTHENTICATION,
    AUTHENTICATION_RESPONSE,
    PLAY,
    PLAY_RESPONSE,
    STOP,
    STOP_RESPONSE,
    ENCRYPTED,
    ERROR
};

/**
 * 协议魔数工具类
 * 提供魔数与字符串的转换以及高效匹配功能
 */
class ProtocolMagicHelper {
public:
    // 获取魔数对应的字节数组
    static std::vector<uint8_t> get_magic_bytes(ProtocolMagic magic);

    // 获取魔数对应的字符串
    static std::string_view get_magic_string(ProtocolMagic magic);

    // 从字符串匹配魔数
    static std::optional<ProtocolMagic> from_string(std::string_view str);

    // 获取最大魔数长度
    static size_t max_magic_length();

    // 获取最小魔数长度
    static size_t min_magic_length();

    /**
     * 高效匹配协议魔数（滑动窗口搜索）
     *
     * 算法优化：
     * 1. 使用首字节索引快速过滤不可能的候选
     * 2. 直接进行字节级别比较
     * 3. 实现滑动窗口，自动扫描整个 buffer
     * 4. 优先匹配更长的魔数（更具体的协议）
     *
     * @param buffer 待匹配的字节缓冲区
     * @param size 缓冲区大小
     * @param offset 输出参数：如果匹配成功，返回魔数结束位置的偏移量
     * @return 匹配的枚举值，如果没有匹配则返回 nullopt
     */
    static std::optional<ProtocolMagic> match(const uint8_t* buffer, size_t size, size_t& offset);

private:
    struct MagicInfo {
        ProtocolMagic magic;
        std::string name;
        std::vector<uint8_t> bytes;
    };

    // 所有魔数信息（延迟初始化）
    static const std::vector<MagicInfo>& get_all_magics();

    // 按首字节分组的魔数映射（延迟初始化）
    static const std::map<uint8_t, std::vector<const MagicInfo*>>& get_magic_by_first_byte();
};

// 便捷函数
inline std::vector<uint8_t> to_bytes(ProtocolMagic magic) {
    return ProtocolMagicHelper::get_magic_bytes(magic);
}

inline std::string_view to_string(ProtocolMagic magic) {
    return ProtocolMagicHelper::get_magic_string(magic);
}

const size_t MAX_MAGIC_LENGTH = ProtocolMagicHelper::max_magic_length();
const size_t MIN_MAGIC_LENGTH = ProtocolMagicHelper::min_magic_length();
