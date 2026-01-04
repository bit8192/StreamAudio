//
// Created by Bincker on 2025/6/26.
//

#include "../../logger.h"
#include "../audio_server.h"
#include "../../exceptions.h"

constexpr auto AUDIO_SERVER_LOGTAG = "audio_server";

AudioServer::AudioServer(const int port, const struct audio_info& audio_info) : port(port),
                                                                               sign_key_pair(Crypto::ED25519::empty()),
                                                                               audio_info(audio_info) {
    init_client_key();
    // 1. 创建socket文件描述符
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket < 0) throw SocketException("无法创建socket");

    // 2. 配置socket地址结构
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port); // 端口转换为网络字节序

    // 3. 绑定socket到地址和端口
    if (bind(server_socket, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0) {
        close(server_socket);
        throw SocketException("绑定失败");
    }

    // 4. 监听连接
    if (listen(server_socket, SOMAXCONN) < 0) {
        close(server_socket);
        throw SocketException("监听失败");
    }
}

void AudioServer::accept_connections() {
    while (running) {
        sockaddr_storage client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_socket = accept(server_socket, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);

        if (client_socket < 0) {
            if (running) {
                Logger::e(AUDIO_SERVER_LOGTAG, "accept failed. errno=" + std::to_string(errno));
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
        const auto len = recv(client.socket_fd, buffer, PACKAGE_SIZE, 0);
        if (len <= 0) {
            if (len == 0) {
                Logger::i(AUDIO_SERVER_LOGTAG, "Client disconnected");
            } else {
                Logger::e(AUDIO_SERVER_LOGTAG, "receive data failed. errno=" + std::to_string(errno));
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
    close(client.socket_fd);
}

AudioServer::~AudioServer() {
    running = false;

    // Close server socket to unblock accept
    close(server_socket);

    // Wait for accept thread
    if (accept_thread.joinable()) {
        accept_thread.join();
    }

    // Close all client connections and wait for threads
    {
        std::lock_guard lock(clients_mutex);
        for (auto& client : clients) {
            client.connected = false;
            close(client.socket_fd);
            if (client.recv_thread.joinable()) {
                client.recv_thread.join();
            }
        }
        clients.clear();
    }
}
