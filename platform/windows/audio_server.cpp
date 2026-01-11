//
// Created by Bincker on 2025/6/26.
//

#include "../audio_server.h"

#include <fstream>
#include <future>

#include "../../exceptions.h"
#include "../../logger.h"
#include "../../tools/string.h"
#include "../../tools/crypto.h"
#include "../../device.h"

constexpr auto AUDIO_SERVER_LOGTAG = "audio_server";

AudioServer::AudioServer(const int port, const struct audio_info &audio_info): port(port),
                                                                               sign_key_pair(Crypto::ED25519::empty()),
                                                                               audio_info(audio_info) {
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

        accept_device(client_socket, client_addr);

        Logger::i(AUDIO_SERVER_LOGTAG, "New client connected");
    }
}

void AudioServer::close_socket() const {
    // Close server socket to unblock accept
    closesocket(server_socket);
}

