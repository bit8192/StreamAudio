//
// Created by Bincker on 2025/6/25.
//

#include "exceptions.h"

AudioException::AudioException(const char *msg): msg(msg) {
}

const char *AudioException::what() const
_GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW{
        return msg;
}

SocketException::SocketException(const char *msg): msg(msg) {
}

const char *SocketException::what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW {
    return msg;
}
