//
// Created by bincker on 2025/7/2.
//

#ifndef BASE64_H
#define BASE64_H
#include <cstdint>
#include <string>
#include <vector>


namespace Base64 {
    std::string encode(const std::vector<uint8_t>& data);
    std::string encode(const uint8_t* data, std::size_t size);
    std::vector<uint8_t> decode(const std::string& data);
};


#endif //BASE64_H
