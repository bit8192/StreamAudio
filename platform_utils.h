//
// Created by bincker on 2025/7/9.
//

#ifndef PLATFORM_UTILS_H
#define PLATFORM_UTILS_H
#include <string>
#include <vector>


namespace PlatformUtils {
    // 获取本机所有非回环 IPv4 地址
    std::vector<std::string> get_local_ip_addresses();

    // 获取首选的本机 IP 地址（优先返回局域网地址）
    std::string get_preferred_ip_address();

    // 是否已配置开机启动
    bool is_auto_start_enabled();

    // 配置/取消开机启动（失败返回 false）
    bool set_auto_start_enabled(bool enabled, std::string* error = nullptr);
};



#endif //PLATFORM_UTILS_H
