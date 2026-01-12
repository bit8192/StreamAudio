#pragma once

#include "platform/socket.h"
#include "device_config.h"
#include "message.h"
#include "tools/crypto.h"
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <list>
#include <chrono>

// 前向声明，避免循环依赖
class AudioServer;

/**
 * 设备客户端类
 * 管理与服务器的连接、认证和消息通信
 */
class Device {
public:
    using MessageCallback = std::function<void(const Message&)>;
    using ErrorCallback = std::function<void(const std::string&)>;

    explicit Device(std::shared_ptr<AudioServer> server, DeviceConfig config, long msg_wait_timeout = 5000);
    explicit Device(std::shared_ptr<AudioServer> server, socket_t socket_fd, long msg_wait_timeout = 5000);
    ~Device();

    // 禁止拷贝
    Device(const Device&) = delete;
    Device& operator=(const Device&) = delete;

    // 连接管理
    void connect();
    void disconnect();
    [[nodiscard]] bool is_connected() const;
    void start_listening();

    // ECDH 密钥交换
    void ecdh(const Crypto::X25519& key_pair);

    // 获取会话密钥
    const std::vector<uint8_t>& get_session_key() const { return session_key; }
    bool is_ecdh_completed() const { return ecdh_completed; }

    // 发送消息
    void send_message(const Message& msg);

    // 消息处理
    void set_message_callback(MessageCallback callback);
    void set_error_callback(ErrorCallback callback);

    // 等待指定消息响应（阻塞）
    std::optional<Message> wait_for_message(ProtocolMagic magic, int32_t msg_id, long timeout_ms = 5000);

    // 获取配置
    const DeviceConfig& get_config() const { return config; }

    // 获取消息 ID 和队列编号
    int32_t get_next_message_id();
    int32_t get_next_queue_num();

private:
    std::shared_ptr<AudioServer> server_;
    DeviceConfig config;
    long msg_wait_timeout;

    // 网络相关
    socket_t socket_fd;
    std::atomic<bool> connected;

    // 加密相关
    std::vector<uint8_t> session_key;
    std::atomic<bool> ecdh_completed;
    std::shared_ptr<Crypto::ED25519> public_key; // 服务器的公钥

    // 消息管理
    std::atomic<int32_t> message_id_counter;
    std::atomic<int32_t> queue_num_counter;

    // 线程和同步
    std::thread listen_thread;
    std::mutex message_queue_mutex;
    std::condition_variable message_cv;
    std::list<Message> received_messages;

    // 回调函数
    MessageCallback message_callback;
    ErrorCallback error_callback;
    std::mutex callback_mutex;

    // 内部方法
    static bool parse_address(const std::string& address, std::string& host, int& port);
    void listening_loop();
    void handle_received_message(const Message& msg);
    void check_connection() const;

    ssize_t socket_send(const uint8_t* data, size_t len) const;
    ssize_t socket_recv(uint8_t* buffer, size_t len) const;
    void close_socket();
    void close_connection(); // 内部方法：停止连接但不等待线程
};
