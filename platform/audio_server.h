//
// Created by Bincker on 2025/6/26.
//

#ifndef STREAMSOUND_AUDIO_SERVER_H
#define STREAMSOUND_AUDIO_SERVER_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <condition_variable>

#pragma comment(lib, "ws2_32.lib")  // 这行是关键
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <condition_variable>
#include <thread>

class AudioServer {
private:
    int server_socket;
    int client_socket = -1;
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    bool running = false;
    std::thread accept_thread;
    void accept_runner();
    std::mutex mutex_wait_client;
    std::condition_variable cv_wait_client;
public:
    AudioServer(const char* ip, int port);

    bool wait_client(const std::chrono::milliseconds& duration);

    void start();

    bool send_data(const char* data, int size);

    virtual ~AudioServer();
};


#endif //STREAMSOUND_AUDIO_SERVER_H
