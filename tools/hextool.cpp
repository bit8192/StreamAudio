//
// Created by bincker on 2026/1/12.
//

#include "hextool.h"

#include <stdexcept>

constexpr char hex_chars[] = "0123456789abcdef";

std::string HEX_TOOL::to_hex(const uint8_t *data, const size_t size) {
    std::string result;
    result.reserve(size * 2);

    for (size_t i = 0; i < size; ++i) {
        uint8_t byte = data[i];
        result.push_back(hex_chars[byte >> 4]);    // 高4位
        result.push_back(hex_chars[byte & 0x0F]);  // 低4位
    }
    return result;
}

std::string HEX_TOOL::to_hex(const std::vector<uint8_t> &data) {
    return to_hex(data.data(), data.size());
}

std::vector<uint8_t> HEX_TOOL::hex_to_bytes(const std::string &hex) {
    if (hex.length() % 2 != 0) throw std::invalid_argument("Invalid hex string");
    std::vector<uint8_t> result(hex.size() / 2);
    for (size_t i = 0; i < result.capacity(); i ++) {
        size_t&& index = i*2;
        const char& c1 = hex.at(index);
        const char& c2 = hex.at(index + 1);
        const uint8_t&& b1 = c1 - (c1 > '9' ? (c1 > 'Z' ? 'a' : 'A') - 10 : '0');
        const uint8_t&& b2 = c2 - (c2 > '9' ? (c2 > 'Z' ? 'a' : 'A') - 10 : '0');
        result[i] = b1 << 4 | b2;
    }
    return result;
}
