//
// Created by Bincker on 2025/6/25.
//

#ifndef STREAMSOUND_EXCEPTIONS_H
#define STREAMSOUND_EXCEPTIONS_H

#include <exception>

class AudioException: public std::exception {
private:
    const char* msg;
public:
    explicit AudioException(const char* msg);
    [[nodiscard]] const char *what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW override;
};

class SocketException: public std::exception {
private:
    const char* msg;
public:
    explicit SocketException(const char* msg);
    [[nodiscard]] const char *what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW override;
};

#endif //STREAMSOUND_EXCEPTIONS_H
