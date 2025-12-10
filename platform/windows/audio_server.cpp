//
// Created by Bincker on 2025/6/26.
//

#include "../audio_server.h"

#include <filesystem>
#include <fstream>
#include <future>

#include "../../exceptions.h"
#include "../../logger.h"
#include "../../tools/string.h"
#include "../../tools/base64.h"
#include "../../tools/crypto.h"

constexpr auto AUDIO_SERVER_LOGTAG = "audio_server";

AudioServer::AudioServer(const int port, const struct audio_info &audio_info): port(port),
                                                                               sign_key_pair(Crypto::ED25519::empty()),
                                                                               audio_info(audio_info) {
    init_client_key();
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        throw SocketException("socket init failed.");
    server_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP);
    if (server_socket == INVALID_SOCKET) {
        const auto error = "socket create failed. error=" + std::to_string(WSAGetLastError());
        throw SocketException(error.c_str());
    }
    char no = 0;
    setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));

    sockaddr_in6 server_addr{};
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(port);

    if (bind(server_socket, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        throw SocketException("bind failed");
    }
}

bool operator==(const sockaddr_storage &lhs, const sockaddr_storage &rhs) {
    // 首先比较地址族
    if (lhs.ss_family != rhs.ss_family) {
        return false;
    }

    // 根据地址族类型进行具体比较
    switch (lhs.ss_family) {
        case AF_INET: {
            auto a4 = (sockaddr_in *) &lhs;
            auto b4 = (sockaddr_in *) &rhs;
            return a4->sin_port == b4->sin_port &&
                   memcmp(&a4->sin_addr, &b4->sin_addr, sizeof(a4->sin_addr)) == 0;
        }
        case AF_INET6: {
            auto a6 = (sockaddr_in6 *) &lhs;
            auto b6 = (sockaddr_in6 *) &rhs;
            return a6->sin6_port == b6->sin6_port &&
                   memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0 &&
                   a6->sin6_flowinfo == b6->sin6_flowinfo &&
                   a6->sin6_scope_id == b6->sin6_scope_id;
        }
        default:
            return false; // 未知地址族
    }
}

std::optional<std::reference_wrapper<client_info>> AudioServer::find_client(const sockaddr_storage &addr) {
    for (client_info &c: clients) {
        if (c.address == addr) {
            return c;
        }
    }
    return std::nullopt;
}

void AudioServer::receive_data() {
    char buffer[PACKAGE_SIZE];
    sockaddr_storage client_addr{};
    int addr_len = sizeof(client_addr);
    while (running) {
        const int len = recvfrom(server_socket, buffer, PACKAGE_SIZE, 0, reinterpret_cast<sockaddr *>(&client_addr),
                                 &addr_len);
        if (len == SOCKET_ERROR) {
            Logger::e(AUDIO_SERVER_LOGTAG, "receive data failed. status=" + std::to_string(len));
            continue;
        }
        auto client_opt = find_client(client_addr);
        if (!client_opt.has_value()) {
            auto& client = clients.emplace_back(client_addr);
            client_opt.emplace(client);
        }
        try {
            handle_message(client_addr, reinterpret_cast<const uint8_t *>(buffer), len, client_opt.value());
        } catch (const std::exception &e) {
            Logger::e(AUDIO_SERVER_LOGTAG, "handle message failed.", e);
        }
    }
}

AudioServer::~AudioServer() {
    running = false;
    closesocket(server_socket);
}
