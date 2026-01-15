//
// Created by Bincker on 2025/6/26.
//

#include "../../logger.h"
#include "../audio_server.h"
#include "../../device.h"
#include "../../exceptions.h"

constexpr auto AUDIO_SERVER_LOGTAG = "audio_server";

AudioServer::AudioServer(const int port, const audio_info& audio_info, std::shared_ptr<Crypto::ED25519> sign_key_pair):
port(port),
sign_key_pair(std::move(sign_key_pair)),
audio_info_(audio_info) {
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

        accept_device(client_socket, client_addr);

        Logger::i(AUDIO_SERVER_LOGTAG, "New client connected");
    }
}

void AudioServer::close_socket() const {
    // Close server socket to unblock accept
    close(server_socket);
}