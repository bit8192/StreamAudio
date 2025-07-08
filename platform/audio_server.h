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
constexpr uint8_t PACK_TYPE_AUDIO_INFO =    0b00100001;
constexpr uint8_t PACK_TYPE_AUDIO_STOP =    0b00100010;
constexpr uint8_t PACK_TYPE_AUDIO_DATA =    0b00100100;


constexpr uint8_t PACK_TYPE_ENCRYPTED_DATA =    0b01000000;//加密数据
constexpr uint8_t PACK_TYPE_SIGN_DATA =    0b01000001;//加密数据，带签名

typedef struct key_info {
    std::string method;
    ED25519 key;
    std::string name;
} key_info;

typedef struct client_info {
    sockaddr_storage address;
    std::chrono::system_clock::time_point active_time;
    std::unique_ptr<X25519> ecdh_pub_key;
    std::vector<uint8_t> session_key;
    key_info* key = nullptr;
    bool play = false;
} client_info;

class AudioServer final {
    int port;
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
    void handle_message(const sockaddr_storage& addr, const char* data, int length, client_info *client = nullptr, const bool& is_encrypted = false, const bool& is_signed = false);
public:
    AudioServer(int port, const struct audio_info& audio_info);

    void start();

    void send_to_all(const std::vector<uint8_t>& data) const;

    void send_to_client(const client_info* client, const std::vector<uint8_t>& data) const;

    int send_to(const sockaddr_storage& addr, const std::vector<uint8_t>& data) const;

    void authenticate(const std::string& code);

    ~AudioServer();
};


#endif //STREAMSOUND_AUDIO_SERVER_H
