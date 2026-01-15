//
// Created by bincker on 2025/6/29.
//
#include <filesystem>
#include <fstream>
#include <algorithm>

#include "audio_server.h"
#include "../logger.h"
#include "openssl/rand.h"
#include "../tools/string.h"
#include "../config.h"
#include "../device.h"

constexpr char LOG_TAG[] = "audio_server_common";
const auto CONFIG_PATH = HOME_DIR / ".config" / "stream-sound";
const auto SIGN_KEY_FILE = CONFIG_PATH / "sign-key.pem";
const auto AUTHENTICATED_FILE = CONFIG_PATH / ".authenticated";

AudioServer::~AudioServer() {
    running = false;
    destructing = true; // 标记正在析构

    // 通知清理线程退出
    cleanup_cv.notify_all();

    // 复制设备列表，避免在持有锁时调用 disconnect()
    std::vector<std::unique_ptr<Device>> devices_to_cleanup;
    {
        std::lock_guard lock(devices_mutex);
        devices_to_cleanup = std::move(devices_);
    }

    // 在锁外断开所有设备
    for (const auto& device : devices_to_cleanup) {
        device->disconnect();
    }

    close_socket();

    // Wait for threads
    if (accept_thread.joinable()) {
        accept_thread.join();
    }
    if (cleanup_thread.joinable()) {
        cleanup_thread.join();
    }
}


std::vector<uint8_t> decrypt(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
    const std::vector iv(data.data(), data.data() + 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data());

    const std::vector cipher_data(data.data() + 16, data.data() + data.size() - 16);
    int len;
    std::vector<uint8_t> plain_data(data.size() - 16);
    EVP_DecryptUpdate(ctx, plain_data.data(), &len, cipher_data.data(), cipher_data.size());
    EVP_DecryptFinal_ex(ctx, plain_data.data() + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    return std::vector(plain_data.data(), plain_data.data() + len);
}

std::vector<uint8_t> encrypt(const uint8_t* data, const size_t len, const std::vector<uint8_t> &key) {
    std::vector<uint8_t> cipher_data(len + 16 + 16);
    RAND_bytes(cipher_data.data(), 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), cipher_data.data());

    int out_len;
    EVP_EncryptUpdate(ctx, cipher_data.data() + 16, &out_len, data, len);
    EVP_EncryptFinal_ex(ctx, cipher_data.data() + 16 + out_len, &out_len);

    EVP_CIPHER_CTX_free(ctx);

    return cipher_data;
}

void AudioServer::accept_device(socket_t socket, const sockaddr_storage& client_addr)
{
    std::lock_guard lock(devices_mutex);
    const auto& device = devices_.emplace_back(std::make_unique<Device>(
        shared_from_this(),
        socket
    ));
    device->start_listening();
}

void AudioServer::start() {
    if (running) {
        running = false;
        cleanup_cv.notify_all();
        if (accept_thread.joinable()) accept_thread.join();
        if (cleanup_thread.joinable()) cleanup_thread.join();
    }
    running = true;
    accept_thread = std::thread(&AudioServer::accept_connections, this);
    cleanup_thread = std::thread(&AudioServer::cleanup_disconnected_devices, this);
}

std::string AudioServer::generate_pair_code() {
    // 生成6位随机数字配对码
    unsigned char random_bytes[3];
    RAND_bytes(random_bytes, 3);

    // 将3字节转换为6位数字 (0-999999)
    uint32_t num = (random_bytes[0] << 16) | (random_bytes[1] << 8) | random_bytes[2];
    num = num % 1000000;

    char code[7];
    snprintf(code, sizeof(code), "%06u", num);
    current_pair_code = code;

    Logger::i(LOG_TAG, "生成配对码: " + current_pair_code);
    return current_pair_code;
}

std::string AudioServer::get_pair_code() const {
    return current_pair_code;
}

void AudioServer::clear_pair_code() {
    current_pair_code.clear();
}

int AudioServer::get_port() const {
    return port;
}

void AudioServer::notify_device_disconnected() {
    cleanup_cv.notify_one();
}

std::vector<uint8_t> AudioServer::ecdh_key(std::vector<uint8_t> key) {
    // 加载客户端公钥
    auto client_public_key = Crypto::X25519::load_public_key_from_mem(key);
    // 使用服务器私钥和客户端公钥派生共享密钥
    return ecdh_key_pair->derive_shared_secret(client_public_key);
}

std::vector<uint8_t> AudioServer::get_ecdh_pub_key_data() const {
    return ecdh_key_pair->export_public_key();
}

std::shared_ptr<Crypto::ED25519> AudioServer::get_sign_key() const {
    return sign_key_pair;
}

void AudioServer::cleanup_disconnected_devices() {
    while (running) {
        std::unique_lock lock(devices_mutex);

        // 等待通知或超时（每10秒检查一次）
        cleanup_cv.wait_for(lock, std::chrono::seconds(10), [this] {
            return !running || destructing;
        });

        // ReSharper disable once CppDFAConstantConditions
        if (!running || destructing) {
            break;
        }

        // 收集需要清理的设备
        std::vector<Device*> devices_to_cleanup;
        for (const auto& device : devices_) {
            if (!device->is_connected() && device->get_config().public_key.empty()) {
                devices_to_cleanup.push_back(device.get());
            }
        }

        // // 释放锁后 disconnect
        // lock.unlock();
        // for (auto* device : devices_to_cleanup) {
        //     Logger::d(LOG_TAG, "Cleaning up disconnected device without public key: " + device->get_config().name);
        //     device->disconnect();
        // }
        //
        // // 重新获取锁，从列表中删除
        // lock.lock();
        devices_.erase(
            std::remove_if(devices_.begin(), devices_.end(),
                [&devices_to_cleanup](const std::unique_ptr<Device>& d) {
                    return std::find(devices_to_cleanup.begin(), devices_to_cleanup.end(), d.get()) != devices_to_cleanup.end();
                }),
            devices_.end()
        );
    }

    Logger::d(LOG_TAG, "Cleanup thread exiting");
}
