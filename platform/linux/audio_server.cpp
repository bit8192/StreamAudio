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
    server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
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
}

void AudioServer::receive_data() {
    char buffer[PACKAGE_SIZE];
    sockaddr_storage client_addr{};
    socklen_t addr_len = sizeof(client_addr);
    while (running) {
        const auto len = recvfrom(server_socket, buffer, PACKAGE_SIZE, 0, reinterpret_cast<sockaddr *>(&client_addr),
                                 &addr_len);
        if (len == -1) {
            Logger::e(AUDIO_SERVER_LOGTAG, "receive data failed. status=" + std::to_string(len));
            continue;
        }
        try {
            handle_message(client_addr, reinterpret_cast<const uint8_t *>(buffer), len);
        } catch (const std::exception &e) {
            Logger::e(AUDIO_SERVER_LOGTAG, "handle message failed.", e);
        }
    }
}

AudioServer::~AudioServer() {
    running = false;
    close(server_socket);
}
