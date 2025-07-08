//
// Created by bincker on 2025/6/29.
//
#include "audio_server.h"
#include "../logger.h"
#include "openssl/rand.h"
#include "../exceptions.h"

constexpr char LOG_TAG[] = "audio_server_common";

bool operator==(const sockaddr_storage &lhs, const sockaddr_storage &rhs) {
        // 首先比较地址族
    if (lhs.ss_family != rhs.ss_family) {
        return false;
    }

    // 根据地址族类型进行具体比较
    switch (lhs.ss_family) {
        case AF_INET: {
            auto a4 = (sockaddr_in*)&lhs;
            auto b4 = (sockaddr_in*)&rhs;
            return a4->sin_port == b4->sin_port &&
                   memcmp(&a4->sin_addr, &b4->sin_addr, sizeof(a4->sin_addr)) == 0;
        }
        case AF_INET6: {
            auto a6 = (sockaddr_in6*)&lhs;
            auto b6 = (sockaddr_in6*)&rhs;
            return a6->sin6_port == b6->sin6_port &&
                   memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0 &&
                   a6->sin6_flowinfo == b6->sin6_flowinfo &&
                   a6->sin6_scope_id == b6->sin6_scope_id;
        }
        default:
            return false; // 未知地址族
    }
}

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

std::vector<uint8_t> encrypt(const std::vector<uint8_t> &data, const std::vector<uint8_t> &key) {
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

void AudioServer::send_to_all(const std::vector<uint8_t> &data) const {
    for (const client_info &client: clients) {
        try {
            sendto(server_socket, reinterpret_cast<const char *>(data.data()), data.size(), 0,
                   (sockaddr *) &client.address, sizeof(client.address));
        } catch (const SocketException &e) {
            Logger::e(LOG_TAG, "send data failed", e);
        }
    }
}

void AudioServer::send_to_client(const client_info *client, const std::vector<uint8_t> &data) const {
    if (client == nullptr) return;
    send_to(client->address, data);
}

int AudioServer::send_to(const sockaddr_storage &addr, const std::vector<uint8_t> &data) const {
    return sendto(server_socket, reinterpret_cast<const char *>(data.data()), static_cast<int>(data.size()), 0, (sockaddr *) &addr, sizeof(addr));
}


void AudioServer::handle_message(const sockaddr_storage &addr, const char *data, const int length, client_info *client,
                                 const bool &is_encrypted, const bool &is_signed) {
    if (length < 1) return;
    char hex[length * 2 + 1];
    hex[length * 2] = 0;
    for (int i = 0; i < length; ++i) {
        sprintf(&hex[i * 2], "%02x", data[i]);
    }

    if (addr.ss_family == AF_INET) {
        Logger::d("AudioServer.handler_message",
                  "receive message: addr=" + std::string(inet_ntoa(((sockaddr_in*)&addr)->sin_addr)) + "\tport=" +
                  std::to_string(ntohs(((sockaddr_in*)&addr)->sin_port)) + "\tdata=" + std::string(hex));
    } else if (addr.ss_family == AF_INET6) {
        const auto addr6 = (sockaddr_in6*) &addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr6->sin6_addr, ip, INET6_ADDRSTRLEN);
        Logger::d("AudioServer.handler_message",
                  "receive message: addr=" + std::string(ip) + "\tport=" +
                  std::to_string(ntohs(addr6->sin6_port)) + "\tdata=" + std::string(hex));
    }
    if (client == nullptr)
        for (client_info &c: clients) {
            if (c.address == addr) {
                client = &c;
                client->active_time = std::chrono::high_resolution_clock::now();
                break;
            }
        }
    std::vector<uint8_t> decrypted_data;
    switch (data[0]) {
        case PACK_TYPE_PING: {
            //ping
            constexpr char res[1] = {PACK_TYPE_PONG};
            send_to(addr, std::vector<uint8_t>(res, res + 1));
            return;
        }
        case PACK_TYPE_PONG: //pong
            return;
        case PACK_TYPE_ECDH_REQUEST: {
            if (client->ecdh_pub_key != nullptr) {
                Logger::e("AudioServer.handle_message", "repeat ecdh. client name=" + client->key->name);
                return;
            }
            client->ecdh_pub_key = std::make_unique<X25519>(
                X25519::load_public_key_from_mem(std::vector<uint8_t>(data + 1, data + length)));
            const auto key = ecdh_key_pair.export_public_key();
            char res[1 + 16 + key.size()] = {};
            auto salt = std::vector<uint8_t>(16);
            RAND_bytes(salt.data(), static_cast<int>(salt.size()));
            client->session_key = ecdh_key_pair.derive_shared_secret(*client->ecdh_pub_key, salt);
            res[0] = PACK_TYPE_ECDH_RESPONSE;
            memcpy(res + 1, salt.data(), salt.size());
            memcpy(res + 1 + 16, key.data(), key.size());
            sendto(server_socket, res, static_cast<int>(1 + 16 + key.size()) + 1, 0, (sockaddr *) &addr,
                   sizeof(sockaddr_in));
            return;
        }
        // case PACK_TYPE_ECDH_RESPONSE: //ignore
        //     return;
        case PACK_TYPE_PAIR_REQUEST:
            if (!is_encrypted) {
                Logger::e("AudioServer.handle_message", "pair request not be encrypt");
                return;
            }
            wait_pair_pub_key = std::make_unique<ED25519>(ED25519::load_public_key_from_mem(
                std::vector<uint8_t>(data + 5, data + length)));
            wait_pair_code = *decrypted_data.data();
            pair_client = client;
            pair_timestamp = std::chrono::high_resolution_clock::now();
        //等待用户输入代码后再发送响应
        // case PACK_TYPE_PAIR_RESPONSE: //ignore
        case PACK_TYPE_AUDIO_START: //audio start
        {
            if (client == nullptr || is_signed) {
                Logger::e("AudioServer.handle_message", "unauthorized client control.");
                return;
            }
            client->play = true;

            std::vector<uint8_t> audio_info_pack(sizeof(audio_info) + 1);
            audio_info_pack[0] = PACK_TYPE_AUDIO_INFO;
            memcpy(&audio_info_pack[1], &audio_info, sizeof(audio_info));
            const auto encrypted_data = encrypt(audio_info_pack, client->session_key);
            char res[1 + encrypted_data.size() + 64];
            res[0] = PACK_TYPE_AUDIO_INFO;
            memcpy(res + 1, encrypted_data.data(), encrypted_data.size());
            const auto sign = sign_key_pair.sign(encrypted_data);
            memcpy(res + 1 + encrypted_data.size(), sign.data(), sign.size());
            sendto(server_socket, res, 1 + encrypted_data.size() + 64, 0, (sockaddr *) &addr, sizeof(sockaddr_in));
            break;
        }
        case PACK_TYPE_AUDIO_STOP: //audio stop
            if (client == nullptr || is_signed) {
                Logger::e("AudioServer.handle_message", "unauthorized client control.");
                return;
            }
            client->play = false;
            break;
        case PACK_TYPE_AUDIO_DATA: //audio data ignore
            break;
        case PACK_TYPE_ENCRYPTED_DATA:
            if (client == nullptr || client->session_key.empty()) {
                Logger::e("AudioServer.handle_message", "invalid sign data: no session key. ");
                return;
            }
            decrypted_data = decrypt(std::vector<uint8_t>(data + 1, data + length), client->session_key);
            handle_message(addr, reinterpret_cast<const char *>(decrypted_data.data()),
                           static_cast<int>(decrypted_data.size()), client, true, is_signed);
            break;
        case PACK_TYPE_SIGN_DATA:
            if (client == nullptr || client->key == nullptr) {
                Logger::e("AudioServer.handle_message", "invalid sign data: no sign public key");
                return;
            }
            if (!client->key->key.verify(std::vector<uint8_t>(data, data + length - 64),
                                         std::vector<uint8_t>(data + length - 64, data + length))) {
                Logger::e("AudioServer.handle_message",
                          "invalid pair request: sign verify failed. client name=" + client->key->name);
                return;
            }
            handle_message(addr, data + 1, length - 65, client, false, true);
            break;
        default:
            Logger::e("AudioServer.handle_message", "unsupported pack type: " + std::to_string(data[0]));
            break;
    }
}

void AudioServer::authenticate(const std::string &code) {
    // std::stoul(code, nullptr, 0);
}
