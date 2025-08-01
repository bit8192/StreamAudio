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
                                                                               ecdh_key_pair(Crypto::X25519::generate()),
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

void AudioServer::start() {
    if (running) {
        running = false;
        if (server_thread.joinable()) server_thread.join();
    }
    running = true;
    server_thread = std::thread(&AudioServer::receive_data, this);
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
        try {
            handle_message(client_addr, reinterpret_cast<const uint8_t *>(buffer), len);
        } catch (const std::exception &e) {
            Logger::e(AUDIO_SERVER_LOGTAG, "handle message failed.", e);
        }
    }
}

AudioServer::~AudioServer() {
    running = false;
    closesocket(server_socket);
}
