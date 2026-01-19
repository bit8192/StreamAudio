//
// Created by Claude on 2026/1/1.
//

#ifndef STREAMAUDIO_CONFIG_H
#define STREAMAUDIO_CONFIG_H

#include <cstdint>
#include <string>
#include <filesystem>

#include "device_config.h"
#include "tools/crypto.h"

#ifdef _WIN32
const auto HOME_DIR = std::filesystem::path(std::getenv("USERPROFILE"));
#else
const auto HOME_DIR = std::filesystem::path(std::getenv("HOME"));
#endif

#define STREAMAUDIO_CONFIG_DEFAULT_PORT 8910

class Config {
public:
    uint16_t port = STREAMAUDIO_CONFIG_DEFAULT_PORT;  // 默认端口
    std::shared_ptr<Crypto::ED25519> private_key; // 签名密钥对
    std::vector<DeviceConfig> devices;

    static std::shared_ptr<Config> load();
    static void save(const std::shared_ptr<Config>& config);

    // 根据设备标识查找设备配置
    // device_identifier: ED25519公钥的SHA256哈希值（32字节）
    DeviceConfig* find_device_by_identifier(const std::vector<uint8_t>& device_identifier);

private:
    static std::shared_ptr<Config> parse_config_file(const std::filesystem::path& config_path);
    static void write_config_file(const std::filesystem::path& config_path, const std::shared_ptr<Config>& config);
};

#endif //STREAMAUDIO_CONFIG_H
