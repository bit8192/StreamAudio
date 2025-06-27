//
// Created by Bincker on 2025/6/26.
//

#include "../audio_server.h"
#include "../../exceptions.h"

AudioServer::AudioServer(const char *ip, int port) {
    // 1. 创建socket文件描述符
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) throw SocketException("无法创建socket");

    // 2. 配置socket地址结构
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip);
    address.sin_port = htons(port); // 端口转换为网络字节序

    // 3. 绑定socket到地址和端口
    if (bind(server_socket, reinterpret_cast<sockaddr *>(&address), sizeof(address)) < 0) {
        close(server_socket);
        throw SocketException("绑定失败");
    }

    // 4. 开始监听连接
    if (listen(server_socket, 0) < 0) { // 最多允许3个连接在队列中等待
        close(server_socket);
        throw SocketException("监听失败");
    }
}

void AudioServer::accept_runner() {
    while (running){
        client_socket = accept(server_socket, reinterpret_cast<sockaddr *>(&client_addr), &client_len);
        while (client_socket > 0){
            {
                std::unique_lock lock(mutex_wait_client);
                cv_wait_client.notify_all();
            }
            std::this_thread::sleep_for(std::chrono::milliseconds (100));
        }
    }
}

bool AudioServer::wait_client(const std::chrono::milliseconds &duration) {
    if (client_socket > 0) return true;
    std::unique_lock lock(mutex_wait_client);
    return cv_wait_client.wait_for(lock, duration) == std::cv_status::no_timeout;
}

void AudioServer::start() {
    if (accept_thread.joinable()){
        running = false;
        accept_thread.join();
    }
    running = true;
    accept_thread = std::thread(&AudioServer::accept_runner, this);
}

bool AudioServer::send_data(const char *data, int size) {
    if (client_socket <= 0) return false;
    if (send(client_socket, data, size, MSG_NOSIGNAL) <= 0){
        close(client_socket);
        client_socket = -1;
        return false;
    }
    return true;
}

AudioServer::~AudioServer() {
    running = false;
    if (accept_thread.joinable()) accept_thread.join();
    close(server_socket);
}
