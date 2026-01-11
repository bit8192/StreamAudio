//
// Created by bincker on 2026/1/12.
//

#include "hextool.h"

constexpr char hex_chars_lower[] = "0123456789abcdef";
constexpr char hex_chars_upper[] = "0123456789ABCDEF";

std::string HEX_TOOL::to_hex(const uint8_t *data, const size_t size, const bool uppercase) {
    const char* hex_chars = uppercase ? hex_chars_upper : hex_chars_lower;
    std::string result;
    result.reserve(size * 2);

    for (size_t i = 0; i < size; ++i) {
        uint8_t byte = data[i];
        result.push_back(hex_chars[byte >> 4]);    // 高4位
        result.push_back(hex_chars[byte & 0x0F]);  // 低4位
    }
    return result;
}
