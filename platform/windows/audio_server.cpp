//
// Created by Bincker on 2025/6/26.
//

#include "../audio_server.h"
#include "../../exceptions.h"
#include "../../logger.h"

const char *AUDIO_SERVER_LOGTAG = "audio_server";

AudioServer::AudioServer(const int port, const struct audio_info &audio_info): audio_info(audio_info) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        throw SocketException("socket init failed.");
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_UDP);
    if (server_socket == INVALID_SOCKET) {
        auto error = "socket create failed. error=" + std::to_string(WSAGetLastError());
        throw SocketException(error.c_str());
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

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
    sockaddr_in client_addr{};
    int addr_len = sizeof(client_addr);
    int len;
    while (running) {
        len = recvfrom(server_socket, buffer, PACKAGE_SIZE, 0, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);
        if (len == SOCKET_ERROR) {
            Logger::e(AUDIO_SERVER_LOGTAG, "receive data failed. status=" + len);
            continue;
        }
        try {
            handle_message(client_addr, buffer, len);
        }catch (const std::exception &e) {
            Logger::e(AUDIO_SERVER_LOGTAG, "handle message failed.", e);
        }
    }
}

void AudioServer::send_data(const char *data, const int size) const {
    for (auto client: clients) {
        try {
            sendto(server_socket, data, size, 0, reinterpret_cast<sockaddr *>(&client), sizeof(client));
        } catch (const SocketException &e) {
            Logger::e(AUDIO_SERVER_LOGTAG, "send data failed", e);
        }
    }
}

AudioServer::~AudioServer() {
    closesocket(server_socket);
}
