//
// Created by bincker on 2025/7/2.
//

#ifndef BASE64_H
#define BASE64_H
#include <cstdint>
#include <string>
#include <vector>


class Base64 {
public:
    static std::string encode(const std::vector<uint8_t>& data);
    static std::string encode(const uint8_t* data, std::size_t size);
    static std::vector<uint8_t> decode(const std::string& data);
};


#endif //BASE64_H
