//
// Created by bincker on 2025/7/2.
//

#include "base64.h"

#include <cmath>
#include <iostream>

constexpr char kBase64Chars[] {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','+','/'
};

constexpr int8_t kBase64Lookup[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0-15
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 16-31
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  // 32-47 ('+'=62, '/'=63)
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  // 48-63 ('0'-'9'=52-61)
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  // 64-79 ('A'-'O')
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  // 80-95 ('P'-'Z')
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  // 96-111 ('a'-'o')
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  // 112-127 ('p'-'z')
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

std::string Base64::encode(const std::vector<uint8_t> &data) {
    return encode(data.data(), data.size());
}

std::string Base64::encode(const uint8_t* data,const size_t size) {
    const size_t encoded_size = (size + 2) / 3 * 4;
    std::string result(encoded_size, '=');

    size_t i = 0, j = 0;
    while (i < size) {
        uint32_t&& octet_a = i < size ? data[i++] : 0;
        uint32_t&& octet_b = i < size ? data[i++] : 0;
        uint32_t&& octet_c = i < size ? data[i++] : 0;

        uint32_t&& triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        result[j++] = kBase64Chars[(triple >> 18) & 0x3F];
        result[j++] = kBase64Chars[(triple >> 12) & 0x3F];
        result[j++] = kBase64Chars[(triple >> 6) & 0x3F];
        result[j++] = kBase64Chars[triple & 0x3F];
    }

    // ReSharper disable once CppDefaultCaseNotHandledInSwitchStatement
    switch (size % 3) {
        case 1: result[encoded_size - 2] = '=';
        case 2: result[encoded_size - 1] = '=';
    }

    return result;
}

uint8_t decode_value(const char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 0;
}

std::vector<uint8_t> Base64::decode(const std::string &data) {
    const size_t&& len = data.size();
    if (len == 0) {
        return {};
    }

    // Base64 字符串长度必须是 4 的倍数，否则非法
    if (len % 4 != 0) {
        throw std::invalid_argument("Base64 input length must be a multiple of 4");
    }

    // 计算输出数据长度（去掉末尾的填充 '='）
    size_t padding = 0;
    if (len >= 1 && data[len - 1] == '=') padding++;
    if (len >= 2 && data[len - 2] == '=') padding++;

    const size_t output_len = (len / 4) * 3 - padding;
    std::vector<uint8_t> result(output_len, 0);

    size_t i = 0;  // 输入索引
    size_t j = 0;  // 输出索引

    while (i < len) {
        // 每次解码 4 个 Base64 字符
        uint32_t&& sextet_a = data[i] == '=' ? 0 : kBase64Lookup[static_cast<uint8_t>(data[i])];
        uint32_t&& sextet_b = data[i + 1] == '=' ? 0 : kBase64Lookup[static_cast<uint8_t>(data[i + 1])];
        uint32_t&& sextet_c = data[i + 2] == '=' ? 0 : kBase64Lookup[static_cast<uint8_t>(data[i + 2])];
        uint32_t&& sextet_d = data[i + 3] == '=' ? 0 : kBase64Lookup[static_cast<uint8_t>(data[i + 3])];

        // 检查是否有非法字符
        if (sextet_a == -1 || sextet_b == -1 || sextet_c == -1 || sextet_d == -1) {
            throw std::invalid_argument("Invalid Base64 character");
        }

        // 合并 4 个 6-bit 值成一个 24-bit 值
        uint32_t&& triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

        // 拆分成 3 个字节（8-bit）
        if (j < output_len) result[j++] = static_cast<uint8_t>((triple >> 16) & 0xFF);
        if (j < output_len) result[j++] = static_cast<uint8_t>((triple >> 8) & 0xFF);
        if (j < output_len) result[j++] = static_cast<uint8_t>(triple & 0xFF);

        i += 4;  // 移动到下一组 4 字符
    }

    return result;
}

