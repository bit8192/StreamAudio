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
#include <filesystem>

#pragma comment(lib, "ws2_32.lib")
const auto HOME_DIR = std::filesystem::path(std::getenv("USERPROFILE"));
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
const auto HOME_DIR = std::filesystem::path(std::getenv("HOME"));
#endif
#include <condition_variable>
#include <map>
#include <thread>
#include <vector>

#include "audio.h"
#include "../tools/crypto.h"
#include "../data_operator.h"

constexpr uint16_t AUDIO_SERVER_VERSION = 0x01;

constexpr int PACKAGE_SIZE = 1200;

constexpr uint8_t PACK_TYPE_PING = 0x00;
constexpr uint8_t PACK_TYPE_PONG = 0x01;


constexpr uint8_t PACK_TYPE_ECDH_REQUEST =              0b00010000;
constexpr uint8_t PACK_TYPE_ECDH_RESPONSE =             0b00010001;
constexpr uint8_t PACK_TYPE_PAIR_REQUEST =              0b00010010;
constexpr uint8_t PACK_TYPE_PAIR_RESPONSE =             0b00010011;
constexpr uint8_t PACK_TYPE_PAIR_COMPLETED =            0b00010100;


constexpr uint8_t PACK_TYPE_AUDIO_START =   0b00100000;
constexpr uint8_t PACK_TYPE_AUDIO_INFO =    0b00100001;
constexpr uint8_t PACK_TYPE_AUDIO_STOP =    0b00100010;
constexpr uint8_t PACK_TYPE_AUDIO_DATA =    0b00100100;


constexpr uint8_t PACK_TYPE_ENCRYPTED_DATA =    0b01000000;//加密数据

struct key_info {
    std::unique_ptr<Crypto::ED25519> key;
    std::string name;
};

struct client_info {
    sockaddr_storage address;
    std::chrono::system_clock::time_point active_time;
    std::unique_ptr<Crypto::X25519> ecdh_pub_key;
    std::vector<uint8_t> session_key;
    key_info* key = nullptr;
    bool play = false;
};

struct data_pack {
    std::unique_ptr<uint8_t[]> data;
    DataOperator data_operator;

    explicit data_pack(const uint8_t pack_type, const size_t size, const uint16_t version = AUDIO_SERVER_VERSION): data(std::make_unique<uint8_t[]>(size)), data_operator(data.get(), size) {
        data_operator.put_uint16(size + 5);
        data_operator.put_uint16(version);
        data_operator.put(pack_type);
    }
};

class AudioServer final {
    int port;
    Crypto::X25519 ecdh_key_pair = Crypto::X25519::generate();
    Crypto::ED25519 sign_key_pair;
    std::vector<uint8_t> wait_pair_pub_key;
    std::vector<uint8_t> wait_pair_hmac;
    std::string wait_pair_client_name;
    std::chrono::system_clock::time_point pair_timestamp;
    client_info* pair_client = nullptr;
    std::map<std::string,key_info> client_keys;
    struct audio_info audio_info;
    int server_socket;
    std::vector<client_info> clients;
    bool running = false;
    std::thread server_thread;
    void receive_data();
    void handle_message(const sockaddr_storage& addr, const uint8_t* ptr, const size_t size, client_info *client = nullptr);
public:
    AudioServer(int port, const struct audio_info& audio_info);

    void start();

    void send_to_all(const data_pack& pack) const;

    void send_to_client(const client_info* client, const data_pack& pack) const;

    void send_to(const sockaddr_storage& addr, const data_pack& pack) const;

    bool pair(const std::string& code, const std::string& name);

    void clear_pair();

    bool has_pair();

    ~AudioServer();
private:
    void init_client_key();

    void add_client_key(key_info& key);

    void delete_client_key(const key_info& key);
};


#endif //STREAMSOUND_AUDIO_SERVER_H
