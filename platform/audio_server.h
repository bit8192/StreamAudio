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
#include "../tools/crypto.h"

constexpr int PACKAGE_SIZE = 1200;

typedef struct client_info {
    sockaddr_in address{};
    std::chrono::system_clock::time_point active_time;
    ED25519* signPubKey = nullptr;
    X25519* ecdhPubKey = nullptr;
} client_info;

typedef struct key_info {
    std::string name;
    ED25519 key;
} key_info;

class AudioServer final {
    X25519 ecdh_key_pair;
    ED25519 sign_key_pair;
    std::vector<key_info> client_keys;
    audio_info audio_info;
    int server_socket;
    std::vector<client_info> clients;
    bool running = false;
    std::thread server_thread;
    void receive_data();
    void handle_message(const sockaddr_in& client, const char* data, int length);
public:
    AudioServer(int port, const struct audio_info& audio_info);

    void start();

    void send_data(const char* data, int size) const;

    ~AudioServer();
};


#endif //STREAMSOUND_AUDIO_SERVER_H
