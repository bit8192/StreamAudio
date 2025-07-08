//
// Created by Bincker on 2025/6/25.
//

#include "exceptions.h"

#include <utility>

AudioException::AudioException(std::string  msg): msg(std::move(msg)) {
}

const char *AudioException::what() const
_GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW{
        return msg.c_str();
}

SocketException::SocketException(std::string  msg): msg(std::move(msg)) {
}

const char *SocketException::what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW {
    return msg.c_str();
}

CryptoException::CryptoException(std::string  msg): msg(std::move(msg)) {
}

const char * CryptoException::what() const noexcept {
    return msg.c_str();
}
