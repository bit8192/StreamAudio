//
// Created by bincker on 2025/6/29.
//
#include <filesystem>
#include <fstream>

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


std::vector<uint8_t> decrypt(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
    const std::vector iv(data.data(), data.data() + 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

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
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), cipher_data.data());

    int out_len;
    EVP_EncryptUpdate(ctx, cipher_data.data() + 16, &out_len, data, len);
    EVP_EncryptFinal_ex(ctx, cipher_data.data() + 16 + out_len, &out_len);

    EVP_CIPHER_CTX_free(ctx);

    return cipher_data;
}

void AudioServer::accept_device(socket_t socket, const sockaddr_storage& client_addr)
{
    std::lock_guard lock(devices_mutex);
    auto& device = devices_.emplace_back(std::make_unique<Device>(
        shared_from_this(),
        socket
    ));
    device->start_listening();
}

void AudioServer::start() {
    if (running) {
        running = false;
        if (accept_thread.joinable()) accept_thread.join();
    }
    running = true;
    accept_thread = std::thread(&AudioServer::accept_connections, this);
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

int AudioServer::get_port() const {
    return port;
}
