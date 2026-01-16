//
// Created by bincker on 2026/1/12.
//

#ifndef STREAMAUDIO_HEXTOOL_H
#define STREAMAUDIO_HEXTOOL_H
#include <cstdint>
#include <string>
#include <vector>


namespace HEX_TOOL {
    std::string to_hex(const uint8_t* data, size_t size);
    std::string to_hex(const std::vector<uint8_t> &data);
    std::vector<uint8_t> hex_to_bytes(const std::string& hex);
};


#endif //STREAMAUDIO_HEXTOOL_H