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
#include "tools/crypto.h"

constexpr char LOG_TAG[] = "Config";
const auto CONFIG_PATH = HOME_DIR / ".config" / "stream-audio";
const auto CONFIG_FILE_PATH = HOME_DIR / ".config" / "stream-audio" / "config.yaml";

void init_server_config(const std::shared_ptr<Config> &config)
{
    config->port = STREAMAUDIO_CONFIG_DEFAULT_PORT;
    config->private_key = Crypto::ED25519::generate();
}

std::shared_ptr<Config> Config::parse_config_file(const std::filesystem::path& config_path) {
    std::shared_ptr<Config> config = std::make_shared<Config>();

    if (!std::filesystem::exists(config_path)) {
        Logger::i(LOG_TAG, "配置文件不存在，使用默认配置");
        init_server_config(config);
        save(config);
        return config;
    }

    try {
        YAML::Node yaml_config = YAML::LoadFile(config_path.string());

        if (yaml_config["port"]) {
            config->port = yaml_config["port"].as<uint16_t>();
            Logger::i(LOG_TAG, "读取配置: port=" + std::to_string(config->port));
        }
        if (yaml_config["private_key"])
        {
            const auto key_pem = yaml_config["private_key"].as<std::string>();
            config->private_key = std::make_shared<Crypto::ED25519>(
                Crypto::ED25519::load_private_key_from_mem(
                    Base64::decode(key_pem)
                )
            );
            Logger::i(LOG_TAG, "读取配置: private_key 已加载");
        }else
        {
            Logger::w(LOG_TAG, "配置文件中缺少 private_key，使用新生成的密钥, 重新生成");
            config->private_key = Crypto::ED25519::generate();
            save(config);
        }

        // 解析设备列表
        if (yaml_config["devices"] && yaml_config["devices"].IsSequence()) {
            for (const auto& device_node : yaml_config["devices"]) {
                DeviceConfig device;
                if (device_node["name"]) {
                    device.name = device_node["name"].as<std::string>();
                }
                if (device_node["address"]) {
                    device.address = device_node["address"].as<std::string>();
                }
                if (device_node["public_key"]) {
                    device.public_key = device_node["public_key"].as<std::string>();
                }
                config->devices.push_back(device);
                Logger::i(LOG_TAG, "读取设备配置: " + device.name + " (" + device.address + ")");
            }
            Logger::i(LOG_TAG, "共加载 " + std::to_string(config->devices.size()) + " 个设备配置");
        }
    } catch (const YAML::Exception& e) {
        Logger::w(LOG_TAG, "解析配置文件失败: " + std::string(e.what()) + ", 使用默认配置");
    } catch (const std::exception& e) {
        Logger::w(LOG_TAG, "读取配置文件失败: " + std::string(e.what()) + ", 使用默认配置");
    }

    return config;
}

void Config::write_config_file(const std::filesystem::path& config_path, const std::shared_ptr<Config>& config) {
    try {
        YAML::Emitter out;
        out << YAML::BeginMap;
        out << YAML::Comment("StreamAudio 配置文件");
        out << YAML::Newline;
        out << YAML::Comment("服务器端口");
        out << YAML::Key << "port";
        out << YAML::Value << config->port;
        out << YAML::Key << "private_key";
        out << YAML::Value << Base64::encode(config->private_key->export_private_key());

        // 保存设备列表
        if (!config->devices.empty()) {
            out << YAML::Newline;
            out << YAML::Comment("已配置的设备列表");
            out << YAML::Key << "devices";
            out << YAML::Value << YAML::BeginSeq;
            for (const auto& device : config->devices) {
                out << YAML::BeginMap;
                out << YAML::Key << "name" << YAML::Value << device.name;
                out << YAML::Key << "address" << YAML::Value << device.address;
                if (!device.public_key.empty()) {
                    out << YAML::Key << "public_key" << YAML::Value << device.public_key;
                }
                out << YAML::EndMap;
            }
            out << YAML::EndSeq;
        }

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

std::shared_ptr<Config> cacheConfig;
std::shared_ptr<Config> Config::load() {
    if (cacheConfig) return cacheConfig;

    // 确保配置目录存在
    if (!std::filesystem::exists(CONFIG_PATH)) {
        std::filesystem::create_directories(CONFIG_PATH);
        Logger::i(LOG_TAG, "创建配置目录: " + CONFIG_PATH.string());
    }

    std::shared_ptr<Config> config = parse_config_file(CONFIG_FILE_PATH);

    // 如果配置文件不存在，创建默认配置文件
    if (!std::filesystem::exists(CONFIG_FILE_PATH)) {
        write_config_file(CONFIG_FILE_PATH, config);
    }

    return config;
}

void Config::save(const std::shared_ptr<Config>& config) {
    // 确保配置目录存在
    if (!std::filesystem::exists(CONFIG_PATH)) {
        std::filesystem::create_directories(CONFIG_PATH);
    }

    write_config_file(CONFIG_FILE_PATH, config);
}

DeviceConfig* Config::find_device_by_identifier(const std::vector<uint8_t>& device_identifier) {
    // 遍历已配对的设备
    for (auto& device : devices) {
        // 解码设备的公钥
        if (device.public_key.empty()) {
            continue;
        }

        try {
            auto device_pubkey = Base64::decode(device.public_key);

            // 计算公钥的SHA256

            // 比较SHA256哈希值
            if (auto pubkey_hash = Crypto::sha256(device_pubkey); pubkey_hash.size() == device_identifier.size()) {
                bool match = true;
                for (size_t i = 0; i < pubkey_hash.size(); ++i) {
                    if (pubkey_hash[i] != device_identifier[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    Logger::d(LOG_TAG, "Found device by SHA256 identifier: " + device.name);
                    return &device;
                }
            }
        } catch (const std::exception& e) {
            Logger::w(LOG_TAG, "Failed to decode device public key: " + std::string(e.what()));
        }
    }

    Logger::d(LOG_TAG, "Device not found by identifier");
    return nullptr;
}
