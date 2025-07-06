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

constexpr uint8_t PACK_TYPE_PING = 0x00;
constexpr uint8_t PACK_TYPE_PONG = 0x01;


constexpr uint8_t PACK_TYPE_ECDH_REQUEST =              0b00010000;
constexpr uint8_t PACK_TYPE_ECDH_RESPONSE =             0b00010001;
constexpr uint8_t PACK_TYPE_PAIR_REQUEST =              0b00010010;
constexpr uint8_t PACK_TYPE_PAIR_RESPONSE =             0b00010011;


constexpr uint8_t PACK_TYPE_AUDIO_START =   0b00100000;
constexpr uint8_t PACK_TYPE_AUDIO_STOP =    0b00100001;
constexpr uint8_t PACK_TYPE_AUDIO_DATA =    0b00100010;

typedef struct key_info {
    std::string method;
    ED25519 key;
    std::string name;
} key_info;

typedef struct client_info {
    sockaddr_in address{};
    std::chrono::system_clock::time_point active_time;
    std::unique_ptr<X25519> ecdh_pub_key = nullptr;
    std::vector<uint8_t> session_key;
    key_info* key;
} client_info;

class AudioServer final {
    X25519 ecdh_key_pair;
    ED25519 sign_key_pair;
    std::unique_ptr<ED25519> wait_pair_pub_key;
    uint32_t wait_pair_code;
    std::chrono::system_clock::time_point pair_timestamp;
    client_info* pair_client;
    std::vector<key_info> client_keys;
    audio_info audio_info;
    int server_socket;
    std::vector<client_info> clients;
    bool running = false;
    std::thread server_thread;
    void receive_data();
    void handle_message(const sockaddr_in& addr, const char* data, int length);
public:
    AudioServer(int port, const struct audio_info& audio_info);

    void start();

    void send_data(const char* data, int size) const;

    ~AudioServer();
};


#endif //STREAMSOUND_AUDIO_SERVER_H
