//
// Created by bincker on 2025/6/29.
//
#include "audio_server.h"
#include "../logger.h"
#include "openssl/rand.h"

bool operator==(const sockaddr_in &lhs, const sockaddr_in &rhs) {
    if (lhs.sin_family != rhs.sin_family) return false;
    if (lhs.sin_port != rhs.sin_port) return false;
    if (lhs.sin_addr.s_addr != rhs.sin_addr.s_addr) return false;
    return true;
}

std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t> & key) {
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

std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t> & key) {
    std::vector<uint8_t> cipher_data(data.size() + 16 + 16);
    RAND_bytes(cipher_data.data(), 16);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), cipher_data.data());

    int len;
    EVP_EncryptUpdate(ctx, cipher_data.data() + 16, &len, cipher_data.data(), cipher_data.size());
    EVP_EncryptFinal_ex(ctx, cipher_data.data() + 16 + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    return cipher_data;
}

void AudioServer::handle_message(const sockaddr_in &addr, const char *data, const int length) {
    if (length < 1) return;
    client_info *client = nullptr;
    for (auto c: clients) {
        if (c.address == addr) {
            client = &c;
            client->active_time = std::chrono::high_resolution_clock::now();
            break;
        }
    }
    std::unique_ptr<char[]> res = nullptr;
    std::vector<uint8_t> decrypted_data;
    const auto pack_type = data[0];
    try {
        switch (pack_type) {
            case PACK_TYPE_PING: //ping
                res = std::make_unique<char[]>(1);
                res[0] = PACK_TYPE_PONG;
                sendto(server_socket, res.get(), 1, 0, (sockaddr *) &addr, sizeof(sockaddr_in));
                return;
            case PACK_TYPE_PONG: //pong
                return;
            case PACK_TYPE_ECDH_REQUEST:
                if (client->ecdh_pub_key != nullptr) {
                    Logger::e("AudioServer.handle_message", "repeat ecdh. client name=" + client->key->name);
                    return;
                }
                client->ecdh_pub_key = std::make_unique<X25519>(X25519::load_public_key_from_mem(std::vector<uint8_t>(data + 1, data + length)));
                const auto key = ecdh_key_pair.export_public_key();
                res = std::make_unique<char[]>(1 + 16 + key.size());
                auto salt = std::vector<uint8_t>(16);
                RAND_bytes(salt.data(), salt.size());
                client->session_key = ecdh_key_pair.derive_shared_secret(*client->ecdh_pub_key, salt);
                res[0] = PACK_TYPE_ECDH_RESPONSE;
                memcpy(res.get() + 1, salt.data(), salt.size());
                memcpy(res.get() + 1 + 16, key.data(), key.size());
                sendto(server_socket, res.get(), key.size() + 1, 0, (sockaddr *) &addr, sizeof(sockaddr_in));
                return;
            case PACK_TYPE_ECDH_RESPONSE://ignore
                return;
            case PACK_TYPE_PAIR_REQUEST:
                if (client->session_key.empty()) {
                    Logger::e("AudioServer.handle_message", "invalid pair request: no session key. client name=" + client->key->name);
                    return;
                }
                decrypted_data = decrypt(std::vector<uint8_t>(data + 1, data + length), client->session_key);
                wait_pair_pub_key = std::make_unique<ED25519>(ED25519::load_public_key_from_mem(std::vector(decrypted_data.data() + 4, decrypted_data.data() + decrypted_data.size())));
                wait_pair_code = *decrypted_data.data();
                pair_client = client;
                pair_timestamp = std::chrono::high_resolution_clock::now();
                //等待用户输入代码后再发送响应
            case PACK_TYPE_PAIR_RESPONSE://ignore
            case PACK_TYPE_AUDIO_START: //audio start
                if (client->session_key.empty()) {
                    Logger::e("AudioServer.handle_message", "invalid pair request: no session key. client name=" + client->key->name);
                    return;
                }
                //TODO 到底要不要加密包类型标识
                decrypted_data = decrypt(std::vector<uint8_t>(data + 1, data + length), client->session_key);
                if (!client->key->key.verify(std::vector<uint8_t>(data, data + 1), std::vector<uint8_t>(data + 1, data + length))) {
                    Logger::e("AudioServer.handle_message", "invalid pair request: sign verify failed. client name=" + client->key->name);
                    return;
                }
                //TODO
                break;
            case PACK_TYPE_AUDIO_STOP: //audio stop
                break;
            case PACK_TYPE_AUDIO_DATA: //audio data ignore
                break;
        }
        delete[] res;
    } catch (...) {
        delete[] res;
    }
}
