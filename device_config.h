#pragma once

#include <string>

/**
 * 设备配置结构
 * 存储设备的基本连接信息
 */
struct DeviceConfig {
    std::string name;        // 设备名称
    std::string address;     // 设备地址（格式: "host:port"）
    std::string public_key;  // 设备的 ED25519 公钥（Base64 编码）

    DeviceConfig() = default;

    DeviceConfig(std::string name, std::string address, std::string public_key = "")
        : name(std::move(name)),
          address(std::move(address)),
          public_key(std::move(public_key)) {}
};
