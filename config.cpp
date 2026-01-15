//
// Created by Claude on 2026/1/11.
// 平台无关的配置文件实现（YAML 格式）
//

#include "config.h"
#include <fstream>
#include <yaml-cpp/yaml.h>

#include "platform/audio_server.h"
#include "logger.h"
#include "tools/base64.h"

constexpr char LOG_TAG[] = "Config";

// 平台相关：返回配置目录路径
std::filesystem::path Config::get_config_directory() {
    return HOME_DIR / ".config" / "stream-sound";
}

std::filesystem::path Config::get_config_file_path() {
    return get_config_directory() / "config.yaml";
}

void init_server_config(ServerConfig& config)
{
    config.port = STREAMAUDIO_CONFIG_DEFAULT_PORT;
    config.private_key = Crypto::ED25519::generate();
}

ServerConfig Config::parse_config_file(const std::filesystem::path& config_path) {
    ServerConfig config;

    if (!std::filesystem::exists(config_path)) {
        Logger::i(LOG_TAG, "配置文件不存在，使用默认配置");
        init_server_config(config);
        save(config);
        return config;
    }

    try {
        YAML::Node yaml_config = YAML::LoadFile(config_path.string());

        if (yaml_config["port"]) {
            config.port = yaml_config["port"].as<uint16_t>();
            Logger::i(LOG_TAG, "读取配置: port=" + std::to_string(config.port));
        }
        if (yaml_config["private_key"])
        {
            const auto key_pem = yaml_config["private_key"].as<std::string>();
            config.private_key = std::make_shared<Crypto::ED25519>(
                Crypto::ED25519::load_private_key_from_mem(
                    Base64::decode(key_pem)
                )
            );
            Logger::i(LOG_TAG, "读取配置: private_key 已加载");
        }else
        {
            Logger::w(LOG_TAG, "配置文件中缺少 private_key，使用新生成的密钥, 重新生成");
            config.private_key = Crypto::ED25519::generate();
            save(config);
        }
    } catch (const YAML::Exception& e) {
        Logger::w(LOG_TAG, "解析配置文件失败: " + std::string(e.what()) + ", 使用默认配置");
    } catch (const std::exception& e) {
        Logger::w(LOG_TAG, "读取配置文件失败: " + std::string(e.what()) + ", 使用默认配置");
    }

    return config;
}

void Config::write_config_file(const std::filesystem::path& config_path, const ServerConfig& config) {
    try {
        YAML::Emitter out;
        out << YAML::BeginMap;
        out << YAML::Comment("StreamAudio 配置文件");
        out << YAML::Newline;
        out << YAML::Comment("服务器端口");
        out << YAML::Key << "port";
        out << YAML::Value << config.port;
        out << YAML::EndMap;

        std::ofstream file(config_path);
        if (!file.is_open()) {
            Logger::e(LOG_TAG, "无法写入配置文件: " + config_path.string());
            return;
        }

        file << out.c_str();
        file.close();

        Logger::i(LOG_TAG, "配置已保存到: " + config_path.string());
    } catch (const std::exception& e) {
        Logger::e(LOG_TAG, "写入配置文件失败: " + std::string(e.what()));
    }
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
