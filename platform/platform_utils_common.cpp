//
// Created by Claude on 2026/1/9.
//

#include "platform_utils.h"
#include <QNetworkInterface>
#include <QHostAddress>

namespace PlatformUtils {

std::vector<std::string> get_local_ip_addresses() {
    std::vector<std::string> addresses;

    const QList<QHostAddress> allAddresses = QNetworkInterface::allAddresses();
    for (const QHostAddress& address : allAddresses) {
        // 只获取 IPv4 地址，排除回环地址
        if (address.protocol() == QAbstractSocket::IPv4Protocol &&
            !address.isLoopback()) {
            addresses.push_back(address.toString().toStdString());
        }
    }

    return addresses;
}

std::string get_preferred_ip_address() {
    std::vector<std::string> addresses = get_local_ip_addresses();

    if (addresses.empty()) {
        return "127.0.0.1";  // 如果没有找到地址，返回回环地址
    }

    // 优先返回局域网地址 (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    for (const auto& addr : addresses) {
        if (addr.starts_with("192.168.") ||
            addr.starts_with("10.") ||
            addr.starts_with("172.")) {
            return addr;
        }
    }

    // 如果没有找到局域网地址，返回第一个地址
    return addresses[0];
}

}
