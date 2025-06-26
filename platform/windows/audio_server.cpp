//
// Created by Bincker on 2025/6/26.
//

#include "../audio_server.h"
#include "../../exceptions.h"

AudioServer::AudioServer(const char *ip, int port) {
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        throw SocketException("socket init failed.");
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        auto error = "socket create failed. error=" + std::to_string(WSAGetLastError());
        throw SocketException(error.c_str());
    }

    // 设置SO_REUSEADDR选项
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR,
               (const char*)&opt, sizeof(opt));

    struct sockaddr_in server_addr{};
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (ip == nullptr || strcmp(ip, "0.0.0.0") == 0) {
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        server_addr.sin_addr.s_addr = inet_addr(ip);
    }

    if (bind(server_socket, (struct sockaddr*)&server_addr,
             sizeof(server_addr)) == SOCKET_ERROR) {
        throw SocketException("bind failed");
    }

    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        throw SocketException("listen failed");
    }
}

void AudioServer::accept_runner() {
    while (running){
        client_socket = accept(server_socket, (struct sockaddr *) &client_addr, &client_len);
        while (client_socket != INVALID_SOCKET){
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void AudioServer::start() {
    if (accept_thread.joinable()){
        running = false;
        accept_thread.join();
    }
    running = true;
    accept_thread = std::thread(&AudioServer::accept_runner, this);
}

void AudioServer::send_data(const char *data, int size) {
    if (client_socket == INVALID_SOCKET) return;
    if (send(client_socket, data, size, 0) == SOCKET_ERROR){
        client_socket = INVALID_SOCKET;
    }
}

AudioServer::~AudioServer() {
    closesocket(server_socket);
}
