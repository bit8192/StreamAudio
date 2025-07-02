//
// Created by bincker on 2025/7/2.
//

#include "base64.h"

#include <cmath>
#include <iostream>

constexpr char BASE64_CHARS[] {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','+','/'
};

std::string Base64::encode(const std::vector<uint8_t> &data) {
    return encode(data.data(), data.size());
}

std::string Base64::encode(const uint8_t *data, const std::size_t size) {
    std::string result(static_cast<size_t>(std::ceil(static_cast<double>(size) * 4 / 3.0)), '=');
    uint8_t prev = 0;
    int prev_len = 0;
    for (size_t i = 0, j = 0; i < size; i++) {
        result[j ++] = BASE64_CHARS[prev | data[i] >> (2 + prev_len)];
        prev_len = prev_len + 8 - 6;
        prev = data[i] & 0xff >> (8 - prev_len);
        if (prev_len == 6) {
            result[j ++] = BASE64_CHARS[prev];
            prev_len = 0;
            prev = 0;
        }else {
            prev <<= 6 - prev_len;
        }
    }
    return result;
}

std::vector<uint8_t> Base64::decode(const std::string &data) {
}
