#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <stdexcept>

/**
 * RAII 封装：管理 Winsock 库的生命周期
 * 构造时初始化 Winsock，析构时自动清理
 * 保证无论程序正常退出还是异常退出都会调用 WSACleanup
 */
class WinsockGuard {
public:
    WinsockGuard() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("Failed to initialize Winsock");
        }
    }

    ~WinsockGuard() {
        WSACleanup();
    }

    // 禁止拷贝和移动
    WinsockGuard(const WinsockGuard&) = delete;
    WinsockGuard& operator=(const WinsockGuard&) = delete;
    WinsockGuard(WinsockGuard&&) = delete;
    WinsockGuard& operator=(WinsockGuard&&) = delete;
};

#define WIN_SOCKET_GUARD_INIT() WinsockGuard winsock_guard;
#else
#define WIN_SOCKET_GUARD_INIT()
#endif // _WIN32
