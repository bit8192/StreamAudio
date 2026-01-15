//
// Created by Bincker on 2025/6/25.
//

#ifndef STREAMAUDIO_EXCEPTIONS_H
#define STREAMAUDIO_EXCEPTIONS_H

#include <exception>
#include <string>

class AudioException final : public std::exception {
    const std::string msg;
public:
    explicit AudioException(std::string  msg);
    [[nodiscard]] const char *what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW override;
};

class SocketException final : public std::exception {
    const std::string msg;
public:
    explicit SocketException(std::string  msg);
    [[nodiscard]] const char *what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW override;
};

class CryptoException final : public std::exception {
    const std::string msg;
public:
    explicit CryptoException(std::string  msg);
    [[nodiscard]] const char *what() const _GLIBCXX_TXN_SAFE_DYN _GLIBCXX_NOTHROW override;
};

#endif //STREAMAUDIO_EXCEPTIONS_H
