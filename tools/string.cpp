//
// Created by bincker on 2025/7/6.
//

#include "string.h"

std::vector<std::string> string::split(const std::string &s, char delim) {
    std::vector<std::string> result;
    size_t pos = 0;
    size_t prev = 0;
    while ((pos = s.find(delim, prev)) != std::string::npos) {
        auto&& item = s.substr(prev, pos - prev);
        if (item.empty()) continue;
        result.emplace_back(item);
        prev = pos + 1;
    }
    return result;
}
