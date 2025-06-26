//
// Created by Bincker on 2025/6/26.
//

#ifndef STREAMSOUND_AUDIO_SERVER_H
#define STREAMSOUND_AUDIO_SERVER_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>

#pragma comment(lib, "ws2_32.lib")  // 这行是关键
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

class AudioServer {
private:
    SOCKET server_socket;
    SOCKET client_socket = INVALID_SOCKET;
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    bool running = false;
    std::thread accept_thread;
    void accept_runner();
public:
    AudioServer(const char* ip, int port);

    void start();

    void send_data(const char* data, int size);

    virtual ~AudioServer();
};


#endif //STREAMSOUND_AUDIO_SERVER_H
