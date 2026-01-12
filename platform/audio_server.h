//
// Created by Bincker on 2025/6/26.
//

#ifndef STREAMSOUND_AUDIO_SERVER_H
#define STREAMSOUND_AUDIO_SERVER_H

#include "socket.h"
#include <condition_variable>
#include <map>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

#include "audio.h"
#include "../tools/crypto.h"
#include "../data_operator.h"

constexpr uint16_t AUDIO_SERVER_VERSION = 0x01;

constexpr int PACKAGE_SIZE = 1200;

constexpr uint8_t PACK_TYPE_PING = 0x00;
constexpr uint8_t PACK_TYPE_PONG = 0x01;


constexpr uint8_t PACK_TYPE_ECDH_REQUEST = 0b00010000;
constexpr uint8_t PACK_TYPE_ECDH_RESPONSE = 0b00010001;
constexpr uint8_t PACK_TYPE_PAIR_REQUEST = 0b00010010;
constexpr uint8_t PACK_TYPE_PAIR_RESPONSE = 0b00010011;
constexpr uint8_t PACK_TYPE_PAIR_COMPLETED = 0b00010100;


constexpr uint8_t PACK_TYPE_AUDIO_START = 0b00100000;
constexpr uint8_t PACK_TYPE_AUDIO_INFO = 0b00100001;
constexpr uint8_t PACK_TYPE_AUDIO_STOP = 0b00100010;
constexpr uint8_t PACK_TYPE_AUDIO_DATA = 0b00100100;


constexpr uint8_t PACK_TYPE_ENCRYPTED_DATA = 0b01000000; //加密数据

struct data_pack {
    std::unique_ptr<uint8_t[]> data;
    DataOperator data_operator;

    explicit data_pack(const uint8_t pack_type, const size_t size,
                       const uint16_t version = AUDIO_SERVER_VERSION) : data(std::make_unique<uint8_t[]>(size)),
                                                                        data_operator(data.get(), size + 5) {
        data_operator.put_uint16(size + 5);
        data_operator.put_uint16(version);
        data_operator.put(pack_type);
    }
};

class Device;

class AudioServer final : public std::enable_shared_from_this<AudioServer> {
    int port;
    std::string current_pair_code;  // 当前配对码
    Crypto::X25519 ecdh_key_pair = Crypto::X25519::generate();
    Crypto::ED25519 sign_key_pair;
    struct audio_info audio_info;
    socket_t server_socket;
    std::vector<std::unique_ptr<Device>> devices_;
    std::mutex devices_mutex; // Protect clients vector
    std::condition_variable cleanup_cv; // 通知清理线程
    bool running = false;
    std::atomic<bool> destructing{false}; // 标记是否正在析构
    std::thread accept_thread; // Thread for accepting new connections
    std::thread cleanup_thread; // Thread for cleaning up disconnected devices
    void accept_connections(); // Accept new TCP connections
    void cleanup_disconnected_devices(); // Clean up disconnected devices without public key


public:
    AudioServer(int port, const struct audio_info &audio_info);

    void start();

    // 生成新的配对码
    std::string generate_pair_code();

    // 获取当前配对码
    [[nodiscard]] std::string get_pair_code() const;

    // 获取端口
    [[nodiscard]] int get_port() const;

    // 通知清理线程检查设备
    void notify_device_disconnected();

    // 交换密钥，生成公共密钥
    std::vector<uint8_t> ecdh_key(std::vector<uint8_t> key);

    // 获取ecdh公钥
    std::vector<uint8_t> get_ecdh_pub_key_data() const;

    ~AudioServer();
private:
    void accept_device(socket_t socket, const sockaddr_storage &client_addr);

    void close_socket() const;
};


#endif //STREAMSOUND_AUDIO_SERVER_H
