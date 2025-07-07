//
// Created by bincker on 2025/7/6.
//

#include "string.h"

std::vector<std::string> string::split(const std::string &s, char delim) {
    std::vector<std::string> result;
    size_t pos = 0;
    size_t prev = 0;
    while ((pos = s.find(delim, prev)) != std::string::npos) {
        auto &&item = s.substr(prev, pos - prev);
        if (item.empty()) continue;
        result.emplace_back(item);
        prev = pos + 1;
    }
    return result;
}

constexpr char DIGITS[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

std::string string::uint32_to_string(uint32_t value, const int &radix) {
    // uint32_t 在 base36 中最多需要 7 个字符 (36^7 > 2^32)
    char buffer[7] = {};
    int i = 6; // 从缓冲区末尾开始填充

    if (value == 0) {
        return "0";
    }

    while (value > 0 && i >= 0) {
        buffer[i--] = DIGITS[value % radix];
        value /= radix;
    }

    return std::string(buffer + i + 1, buffer + sizeof(buffer));
}
