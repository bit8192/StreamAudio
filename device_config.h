#pragma once

#include <cstdint>
#include <string>

enum class AudioEncryptionMethod {
    NONE,
    XOR_256,
    AES128GCM,
    AES256GCM,
};

inline std::string audio_encryption_to_string(const AudioEncryptionMethod method)
{
    switch (method) {
        case AudioEncryptionMethod::NONE:
            return "none";
        case AudioEncryptionMethod::XOR_256:
            return "xor256";
        case AudioEncryptionMethod::AES128GCM:
            return "aes128gcm";
        case AudioEncryptionMethod::AES256GCM:
            return "aes256gcm";
        default:
            return "xor256";
    }
}

inline AudioEncryptionMethod audio_encryption_from_string(const std::string& value)
{
    if (value == "none") {
        return AudioEncryptionMethod::NONE;
    }
    if (value == "aes128gcm") {
        return AudioEncryptionMethod::AES128GCM;
    }
    if (value == "aes256gcm") {
        return AudioEncryptionMethod::AES256GCM;
    }
    return AudioEncryptionMethod::XOR_256;
}

inline uint8_t audio_encryption_to_wire(const AudioEncryptionMethod method)
{
    switch (method) {
        case AudioEncryptionMethod::NONE:
            return 0;
        case AudioEncryptionMethod::XOR_256:
            return 1;
        case AudioEncryptionMethod::AES128GCM:
            return 2;
        case AudioEncryptionMethod::AES256GCM:
            return 3;
        default:
            return 1;
    }
}

inline AudioEncryptionMethod audio_encryption_from_wire(const uint8_t value)
{
    switch (value) {
        case 0:
            return AudioEncryptionMethod::NONE;
        case 2:
            return AudioEncryptionMethod::AES128GCM;
        case 3:
            return AudioEncryptionMethod::AES256GCM;
        case 1:
        default:
            return AudioEncryptionMethod::XOR_256;
    }
}

/**
 * 设备配置结构
 * 存储设备的基本连接信息
 */
struct DeviceConfig {
    std::string name;        // 设备名称
    std::string address;     // 设备地址（格式: "host:port"）
    std::string public_key;  // 设备的 ED25519 公钥（Base64 编码）
    bool auto_play = true;   // 自动播放（默认开启）
    AudioEncryptionMethod audio_encryption = AudioEncryptionMethod::XOR_256;  // 音频流加密方式

    DeviceConfig() = default;

    DeviceConfig(
        std::string name,
        std::string address,
        std::string public_key = "",
        bool auto_play = true,
        AudioEncryptionMethod audio_encryption = AudioEncryptionMethod::XOR_256
    )
        : name(std::move(name)),
          address(std::move(address)),
          public_key(std::move(public_key)),
          auto_play(auto_play),
          audio_encryption(audio_encryption) {}
};
