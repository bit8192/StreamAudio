//
// Created by Claude on 2026/1/1.
//

#include "../config.h"
#include <fstream>
#include <sstream>
#include "../audio_server.h"
#include "../../logger.h"
#include "../../tools/string.h"

constexpr char LOG_TAG[] = "Config";

std::filesystem::path Config::get_config_directory() {
    return HOME_DIR / ".config" / "stream-sound";
}

std::filesystem::path Config::get_config_file_path() {
    return get_config_directory() / "config.ini";
}

ServerConfig Config::parse_config_file(const std::filesystem::path& config_path) {
    ServerConfig config;

    std::ifstream file(config_path);
    if (!file.is_open()) {
        Logger::i(LOG_TAG, "配置文件不存在，使用默认配置");
        return config;
    }

    std::string line;
    while (std::getline(file, line)) {
        // 跳过空行和注释
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }

        // 解析 key=value
        auto parts = string::split(line, '=');
        if (parts.size() != 2) {
            continue;
        }

        std::string key = parts[0];
        std::string value = parts[1];

        // 去除首尾空格
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        if (key == "port") {
            try {
                config.port = static_cast<uint16_t>(std::stoi(value));
                Logger::i(LOG_TAG, "读取配置: port=" + std::to_string(config.port));
            } catch (const std::exception& e) {
                Logger::w(LOG_TAG, "无效的端口配置值: " + value);
            }
        }
    }

    file.close();
    return config;
}

void Config::write_config_file(const std::filesystem::path& config_path, const ServerConfig& config) {
    std::ofstream file(config_path);
    if (!file.is_open()) {
        Logger::e(LOG_TAG, "无法写入配置文件: " + config_path.string());
        return;
    }

    file << "# StreamSound 配置文件\n";
    file << "# 服务器端口\n";
    file << "port=" << config.port << "\n";

    file.close();
    Logger::i(LOG_TAG, "配置已保存到: " + config_path.string());
}

ServerConfig Config::load() {
    const auto config_dir = get_config_directory();
    const auto config_path = get_config_file_path();

    // 确保配置目录存在
    if (!std::filesystem::exists(config_dir)) {
        std::filesystem::create_directories(config_dir);
        Logger::i(LOG_TAG, "创建配置目录: " + config_dir.string());
    }

    ServerConfig config = parse_config_file(config_path);

    // 如果配置文件不存在，创建默认配置文件
    if (!std::filesystem::exists(config_path)) {
        write_config_file(config_path, config);
    }

    return config;
}

void Config::save(const ServerConfig& config) {
    const auto config_dir = get_config_directory();
    const auto config_path = get_config_file_path();

    // 确保配置目录存在
    if (!std::filesystem::exists(config_dir)) {
        std::filesystem::create_directories(config_dir);
    }

    write_config_file(config_path, config);
}
