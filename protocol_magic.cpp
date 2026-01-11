#include "protocol_magic.h"
#include <stdexcept>

// 获取所有魔数信息（延迟初始化）
const std::vector<ProtocolMagicHelper::MagicInfo>& ProtocolMagicHelper::get_all_magics() {
    static std::vector<MagicInfo> all_magics = {
        {ProtocolMagic::ECDH, "ECDH", {}},
        {ProtocolMagic::ECDH_RESPONSE, "ECDH_RESPONSE", {}},
        {ProtocolMagic::PAIR, "PAIR", {}},
        {ProtocolMagic::PAIR_RESPONSE, "PAIR_RESPONSE", {}},
        {ProtocolMagic::AUTHENTICATION, "AUTHENTICATION", {}},
        {ProtocolMagic::AUTHENTICATION_RESPONSE, "AUTHENTICATION_RESPONSE", {}},
        {ProtocolMagic::PLAY, "PLAY", {}},
        {ProtocolMagic::PLAY_RESPONSE, "PLAY_RESPONSE", {}},
        {ProtocolMagic::STOP, "STOP", {}},
        {ProtocolMagic::STOP_RESPONSE, "STOP_RESPONSE", {}},
    };

    // 初始化字节数组（只在第一次调用时执行）
    static bool initialized = false;
    if (!initialized) {
        for (auto& info : all_magics) {
            info.bytes.assign(info.name.begin(), info.name.end());
        }
        initialized = true;
    }

    return all_magics;
}

// 获取按首字节分组的魔数映射（延迟初始化）
const std::map<uint8_t, std::vector<const ProtocolMagicHelper::MagicInfo*>>&
ProtocolMagicHelper::get_magic_by_first_byte() {
    static std::map<uint8_t, std::vector<const MagicInfo*>> mapping;

    // 初始化映射（只在第一次调用时执行）
    static bool initialized = false;
    if (!initialized) {
        const auto& all_magics = get_all_magics();
        for (const auto& info : all_magics) {
            if (!info.bytes.empty()) {
                mapping[info.bytes[0]].push_back(&info);
            }
        }

        // 按魔数长度降序排序（优先匹配更长的）
        for (auto& [byte, list] : mapping) {
            std::sort(list.begin(), list.end(), [](const MagicInfo* a, const MagicInfo* b) {
                return a->bytes.size() > b->bytes.size();
            });
        }

        initialized = true;
    }

    return mapping;
}

std::vector<uint8_t> ProtocolMagicHelper::get_magic_bytes(ProtocolMagic magic) {
    const auto& all_magics = get_all_magics();
    for (const auto& info : all_magics) {
        if (info.magic == magic) {
            return info.bytes;
        }
    }
    throw std::invalid_argument("Invalid ProtocolMagic value");
}

std::string_view ProtocolMagicHelper::get_magic_string(ProtocolMagic magic) {
    const auto& all_magics = get_all_magics();
    for (const auto& info : all_magics) {
        if (info.magic == magic) {
            return info.name;
        }
    }
    throw std::invalid_argument("Invalid ProtocolMagic value");
}

std::optional<ProtocolMagic> ProtocolMagicHelper::from_string(std::string_view str) {
    const auto& all_magics = get_all_magics();
    for (const auto& info : all_magics) {
        if (info.name == str) {
            return info.magic;
        }
    }
    return std::nullopt;
}

size_t ProtocolMagicHelper::max_magic_length() {
    const auto& all_magics = get_all_magics();
    size_t max_len = 0;
    for (const auto& info : all_magics) {
        max_len = std::max(max_len, info.bytes.size());
    }
    return max_len;
}

size_t ProtocolMagicHelper::min_magic_length() {
    const auto& all_magics = get_all_magics();
    if (all_magics.empty()) return 0;

    size_t min_len = all_magics[0].bytes.size();
    for (const auto& info : all_magics) {
        min_len = std::min(min_len, info.bytes.size());
    }
    return min_len;
}

std::optional<ProtocolMagic> ProtocolMagicHelper::match(
    const uint8_t* buffer,
    size_t size,
    size_t& offset
) {
    const auto& magic_map = get_magic_by_first_byte();

    // 滑动窗口：尝试每个可能的起始位置
    for (size_t start = 0; start < size; ++start) {
        if (size - start < MIN_MAGIC_LENGTH) {
            break;
        }

        uint8_t first_byte = buffer[start];

        // 使用首字节索引快速获取候选列表（已按长度降序排序）
        auto it = magic_map.find(first_byte);
        if (it == magic_map.end()) {
            continue;
        }

        const auto& candidates = it->second;

        // 遍历候选，优先匹配更长的（更具体的）协议
        for (const auto* candidate : candidates) {
            size_t magic_len = candidate->bytes.size();
            if (start + magic_len > size) {
                continue;
            }

            // 直接进行字节比较
            bool matched = true;
            for (size_t i = 0; i < magic_len; ++i) {
                if (buffer[start + i] != candidate->bytes[i]) {
                    matched = false;
                    break;
                }
            }

            if (matched) {
                // 匹配成功：返回魔数结束位置的偏移量
                offset = start + magic_len;
                return candidate->magic;
            }
        }
    }

    // 未找到匹配
    return std::nullopt;
}
