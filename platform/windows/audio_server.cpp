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
    server_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
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

    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        throw SocketException("listen failed");
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

void AudioServer::accept_connections() {
    while (running) {
        sockaddr_storage client_addr{};
        int addr_len = sizeof(client_addr);
        const SOCKET client_socket = accept(server_socket, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);

        if (client_socket == INVALID_SOCKET) {
            if (running) {
                Logger::e(AUDIO_SERVER_LOGTAG, "accept failed. error=" + std::to_string(WSAGetLastError()));
            }
            continue;
        }

        {
            std::lock_guard lock(clients_mutex);
            auto& client = clients.emplace_back();
            client.address = client_addr;
            client.socket_fd = client_socket;
            client.active_time = std::chrono::high_resolution_clock::now();
            client.connected = true;

            // Start receive thread for this client
            client.recv_thread = std::thread(&AudioServer::receive_data, this, std::ref(client));
        }

        Logger::i(AUDIO_SERVER_LOGTAG, "New client connected");
    }
}

void AudioServer::receive_data(client_info& client) {
    char buffer[PACKAGE_SIZE];
    while (running && client.connected) {
        const int len = recv(client.socket_fd, buffer, PACKAGE_SIZE, 0);
        if (len <= 0) {
            if (len == 0) {
                Logger::i(AUDIO_SERVER_LOGTAG, "Client disconnected");
            } else {
                Logger::e(AUDIO_SERVER_LOGTAG, "receive data failed. error=" + std::to_string(WSAGetLastError()));
            }
            client.connected = false;
            break;
        }
        try {
            handle_message(client.address, reinterpret_cast<const uint8_t *>(buffer), len, client);
        } catch (const std::exception &e) {
            Logger::e(AUDIO_SERVER_LOGTAG, "handle message failed.", e);
        }
    }
    closesocket(client.socket_fd);
}

AudioServer::~AudioServer() {
    running = false;

    // Close server socket to unblock accept
    closesocket(server_socket);

    // Wait for accept thread
    if (accept_thread.joinable()) {
        accept_thread.join();
    }

    // Close all client connections and wait for threads
    {
        std::lock_guard lock(clients_mutex);
        for (auto& client : clients) {
            client.connected = false;
            closesocket(client.socket_fd);
            if (client.recv_thread.joinable()) {
                client.recv_thread.join();
            }
        }
        clients.clear();
    }
}
