//
// Created by Bincker on 2025/6/26.
//

#ifndef STREAMAUDIO_AUDIO_SERVER_H
#define STREAMAUDIO_AUDIO_SERVER_H

#include "socket.h"
#include <condition_variable>
#include <map>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

#include "audio.h"
#include "../device_config.h"
#include "../tools/crypto.h"
#include "../config.h"

constexpr int PAIR_BYTE_LENGTH = 32;

class Device;

class AudioServer final : public std::enable_shared_from_this<AudioServer> {
    std::shared_ptr<Config> config;
    int port;
    std::string pair_code;  // 当前配对码
    std::shared_ptr<Crypto::X25519> ecdh_key_pair = std::make_shared<Crypto::X25519>(Crypto::X25519::generate());
    std::shared_ptr<Crypto::ED25519> sign_key_pair;
    audio_info audio_info_;
    socket_t server_socket;
    std::vector<std::unique_ptr<Device>> devices_;
    std::mutex devices_mutex; // Protect clients vector
    std::condition_variable cleanup_cv; // 通知清理线程
    bool running = false;
    std::atomic<bool> destructing{false}; // 标记是否正在析构
    std::thread accept_thread; // Thread for accepting new connections
    std::thread cleanup_thread; // Thread for cleaning up disconnected devices

    // Audio streaming related
    std::shared_ptr<Audio> audio_capture;  // 音频捕获对象
    std::thread audio_thread;              // 音频捕获线程
    std::atomic<bool> audio_streaming;     // 音频捕获状态

    void accept_connections(); // Accept new TCP connections
    void cleanup_disconnected_devices(); // Clean up disconnected devices without public key
    void audio_capture_loop(); // 音频捕获循环

public:
    AudioServer(const std::shared_ptr<Config> &config, const audio_info &audio_info, const std::shared_ptr<Audio> &audio);

    void start();

    // 生成配对码
    void generate_pair_code();

    // 获取当前配对码
    [[nodiscard]] std::string get_pair_code() const;

    void clear_pair_code();

    // 获取端口
    [[nodiscard]] int get_port() const;

    // 通知清理线程检查设备
    void notify_device_disconnected();

    // 交换密钥，生成公共密钥
    std::vector<uint8_t> ecdh_key(std::vector<uint8_t> key);

    // 获取ecdh公钥
    std::vector<uint8_t> get_ecdh_pub_key_data() const;

    std::shared_ptr<Crypto::ED25519> get_sign_key() const;

    audio_info get_audio_info() const;

    void save_device_config(const DeviceConfig &device) const;

    // 获取配置对象
    [[nodiscard]] std::shared_ptr<Config> get_config() const { return config; }

    ~AudioServer();
private:
    void accept_device(socket_t socket, const sockaddr_storage &client_addr);

    void close_socket() const;
};


#endif //STREAMAUDIO_AUDIO_SERVER_H
