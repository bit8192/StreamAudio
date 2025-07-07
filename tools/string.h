//
// Created by bincker on 2025/7/6.
//

#ifndef STRING_H
#define STRING_H

#include <cstdint>
#include <string>
#include <vector>

namespace string {
    std::vector<std::string> split(const std::string &s, char delim);

    std::string uint32_to_string(uint32_t i, const int& radix = 10);
}

#endif //STRING_H
