//
// Created by Claude on 2026/1/1.
//

#ifndef STREAMAUDIO_CONFIG_H
#define STREAMAUDIO_CONFIG_H

#include <cstdint>
#include <string>
#include <filesystem>

#include "tools/crypto.h"

#ifdef _WIN32
const auto HOME_DIR = std::filesystem::path(std::getenv("USERPROFILE"));
#else
const auto HOME_DIR = std::filesystem::path(std::getenv("HOME"));
#endif

#define STREAMAUDIO_CONFIG_DEFAULT_PORT 8910

struct ServerConfig {
    uint16_t port = STREAMAUDIO_CONFIG_DEFAULT_PORT;  // 默认端口
    std::shared_ptr<Crypto::ED25519> private_key; // 签名密钥对
};

class Config {
public:
    static ServerConfig load();
    static void save(const ServerConfig& config);

private:
    static ServerConfig parse_config_file(const std::filesystem::path& config_path);
    static void write_config_file(const std::filesystem::path& config_path, const ServerConfig& config);
};

#endif //STREAMAUDIO_CONFIG_H
