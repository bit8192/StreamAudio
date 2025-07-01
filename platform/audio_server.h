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

#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <condition_variable>
#include <thread>
#include <vector>

#include "audio.h"

const int PACKAGE_SIZE = 1200;

typedef struct client_info {
    sockaddr_in address{};
    std::chrono::system_clock::time_point active_time;
} client_info;

class AudioServer {
private:
    audio_info audio_info;
    int server_socket;
    std::vector<client_info> clients;
    bool running = false;
    std::thread server_thread;
    void receive_data();
    void handle_message(const sockaddr_in& client, const char* data, int length);
static char FUN_PING = 0;
public:
    AudioServer(int port, const struct audio_info& audio_info);

    void start();

    void send_data(const char* data, int size) const;

    virtual ~AudioServer();
};


#endif //STREAMSOUND_AUDIO_SERVER_H
