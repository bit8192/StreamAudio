//
// Created by Claude on 2026/1/1.
//

#ifndef STREAMSOUND_CONFIG_H
#define STREAMSOUND_CONFIG_H

#include <cstdint>
#include <string>
#include <filesystem>

#ifdef _WIN32
const auto HOME_DIR = std::filesystem::path(std::getenv("USERPROFILE"));
#else
const auto HOME_DIR = std::filesystem::path(std::getenv("HOME"));
#endif

#define STREAMSOUND_CONFIG_DEFAULT_PORT 8910

struct ServerConfig {
    uint16_t port = STREAMSOUND_CONFIG_DEFAULT_PORT;  // 默认端口
};

class Config {
public:
    static ServerConfig load();
    static void save(const ServerConfig& config);
    static std::filesystem::path get_config_file_path();

private:
    static ServerConfig parse_config_file(const std::filesystem::path& config_path);
    static void write_config_file(const std::filesystem::path& config_path, const ServerConfig& config);
    static std::filesystem::path get_config_directory();
};

#endif //STREAMSOUND_CONFIG_H
