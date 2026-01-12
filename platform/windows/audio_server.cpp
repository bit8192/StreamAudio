//
// Created by Bincker on 2025/6/26.
//

#include "../audio_server.h"

#include <fstream>

#include "../../exceptions.h"
#include "../../logger.h"
#include "../../tools/crypto.h"
#include "../../device.h"

constexpr auto AUDIO_SERVER_LOGTAG = "audio_server";

AudioServer::AudioServer(const int port, const struct audio_info &audio_info): port(port),
                                                                               sign_key_pair(Crypto::ED25519::empty()),
                                                                               audio_info(audio_info) {
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        const auto error = "socket create failed. error=" + std::to_string(WSAGetLastError());
        throw SocketException(error);
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

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

        try {
            accept_device(client_socket, client_addr);

            Logger::i(AUDIO_SERVER_LOGTAG, "New client connected");
        }catch (std::exception &e) {
            char address[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr, address, INET_ADDRSTRLEN);
            Logger::e(AUDIO_SERVER_LOGTAG, "accept client failed: {}\t{}", address, e.what());
        }catch(...) {
            char address[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr, address, INET_ADDRSTRLEN);
            Logger::e(AUDIO_SERVER_LOGTAG, "accept client failed: {}", address);
        }
    }
}

void AudioServer::close_socket() const {
    // Close server socket to unblock accept
    closesocket(server_socket);
}

