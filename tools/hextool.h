//
// Created by bincker on 2026/1/12.
//

#ifndef STREAMAUDIO_HEXTOOL_H
#define STREAMAUDIO_HEXTOOL_H
#include <cstdint>
#include <string>


namespace HEX_TOOL {
    std::string to_hex(const uint8_t* data, size_t size, bool uppercase = false);
};


#endif //STREAMAUDIO_HEXTOOL_H