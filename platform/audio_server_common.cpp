//
// Created by bincker on 2025/6/29.
//
#include "audio_server.h"
#include "../logger.h"
#include "openssl/rand.h"
#include "../exceptions.h"
#include "../data_operator.h"

constexpr char LOG_TAG[] = "audio_server_common";

bool operator==(const sockaddr_storage &lhs, const sockaddr_storage &rhs) {
    // 首先比较地址族
    if (lhs.ss_family != rhs.ss_family) {
        return false;
    }

    // 根据地址族类型进行具体比较
    switch (lhs.ss_family) {
        case AF_INET: {
            auto a4 = (sockaddr_in *) &lhs;
            auto b4 = (sockaddr_in *) &rhs;
            return a4->sin_port == b4->sin_port &&
                   memcmp(&a4->sin_addr, &b4->sin_addr, sizeof(a4->sin_addr)) == 0;
        }
        case AF_INET6: {
            auto a6 = (sockaddr_in6 *) &lhs;
            auto b6 = (sockaddr_in6 *) &rhs;
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

void AudioServer::send_to_all(const data_pack &pack) const {
    sockaddr_in client_addr{};
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    client_addr.sin_port = htons(port);
    const auto result = sendto(server_socket, reinterpret_cast<const char *>(pack.data.get()), pack.data_operator.remaining(), 0,
           (sockaddr *) &client_addr, sizeof(client_addr));
    if ( result < 1 ) {
        Logger::e("AudioServer::send_to_all", "send failed: " + std::to_string(result));
    }else if (result < pack.data_operator.remaining()) {
        Logger::e("AudioServer::send_to_all", "not sent completely: " + std::to_string(result) + "/" + std::to_string(pack.data_operator.remaining()));
    }
}

void AudioServer::send_to_client(const client_info *client, const data_pack &pack) const {
    if (client == nullptr) return;
    send_to(client->address, pack);
}

void AudioServer::send_to(const sockaddr_storage &addr, const data_pack &pack) const {
    const auto result = sendto(server_socket, reinterpret_cast<const char *>(pack.data.get()),
                               static_cast<int>(pack.data_operator.remaining()), 0,
                               (sockaddr *) &addr, sizeof(addr));
    if ( result < 1 ) {
        Logger::e("AudioServer::send_to", "send failed: " + std::to_string(result));
    }else if (result < pack.data_operator.remaining()) {
        Logger::e("AudioServer::send_to", "not sent completely: " + std::to_string(result) + "/" + std::to_string(pack.data_operator.remaining()));
    }
}

std::vector<uint8_t> read_key_value(DataOperator& data_pointer) {
    const auto key_length = data_pointer.get_uint16();
    if (key_length < 1 || key_length > 1024) {
        throw SocketException("invalid ecdh key length: " + std::to_string(key_length));
    }
    if (data_pointer.remaining() < key_length) {
        throw SocketException("pack length is insufficient: need=" + std::to_string(key_length));
    }
    return data_pointer.get_array(key_length);
}

void AudioServer::handle_message(const sockaddr_storage &addr, const uint8_t* ptr, const size_t size, client_info *client) {
    if (size < 1) return;

    auto data_operator = DataOperator(ptr, size);

    if (addr.ss_family == AF_INET) {
        Logger::d("AudioServer.handler_message",
                  "receive message: addr=" + std::string(inet_ntoa(((sockaddr_in *) &addr)->sin_addr)) + "\tport=" +
                  std::to_string(ntohs(((sockaddr_in *) &addr)->sin_port)) + "\tdata=" + data_operator.to_hex());
    } else if (addr.ss_family == AF_INET6) {
        const auto addr6 = (sockaddr_in6 *) &addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr6->sin6_addr, ip, INET6_ADDRSTRLEN);
        Logger::d("AudioServer.handler_message",
                  "receive message: addr=" + std::string(ip) + "\tport=" +
                  std::to_string(ntohs(addr6->sin6_port)) + "\tdata=" + data_operator.to_hex());
    }
    if (client == nullptr)
        for (client_info &c: clients) {
            if (c.address == addr) {
                client = &c;
                client->active_time = std::chrono::high_resolution_clock::now();
                break;
            }
        }

    const uint16_t& pack_length = data_operator.get_uint16();
    const uint16_t& pack_version = data_operator.get_uint16();

    if (pack_length > PACKAGE_SIZE) {
        Logger::e("AudioServer.handler_message", "unsupported subpackage.");
        return;
    }
    if (pack_version > AUDIO_SERVER_VERSION) {
        Logger::e("AudioServer.handler_message", "unsupported version:" + std::to_string(pack_version));
        return;
    }

check_pack_type:
    switch (data_operator.get()) {
        case PACK_TYPE_PING: {
            //ping
            data_pack pack{PACK_TYPE_PONG, 0};
            send_to(client->address, pack);
            return;
        }
        case PACK_TYPE_PONG: //pong
            return;
        case PACK_TYPE_ECDH_REQUEST: {
            if (client->ecdh_pub_key != nullptr) {
                Logger::e("AudioServer.handle_message", "repeat ecdh. client name=" + client->key->name);
                return;
            }
            client->ecdh_pub_key = std::make_unique<Crypto::X25519>(Crypto::X25519::load_public_key_from_mem(read_key_value(&p_pack, p_pack_end)));
            const auto key = ecdh_key_pair.export_public_key();
            const int send_pack_len = 1 + 16 + 2 + key.size();
            char res[send_pack_len] = {};
            char* res_p = res;
            auto salt = std::vector<uint8_t>(16);
            RAND_bytes(salt.data(), static_cast<int>(salt.size()));
            client->session_key = ecdh_key_pair.derive_shared_secret(*client->ecdh_pub_key, salt);
            *res_p = PACK_TYPE_ECDH_RESPONSE;                                   res_p += sizeof(PACK_TYPE_ECDH_RESPONSE);
            memcpy(res_p, salt.data(), salt.size());                        res_p += salt.size();
            *reinterpret_cast<short *>(res_p) = static_cast<short>(key.size()); res_p += sizeof(short);
            memcpy(res_p, key.data(), key.size());
            sendto(server_socket, res, send_pack_len, 0, (sockaddr *) &addr,sizeof(sockaddr_in));
            return;
        }
        // case PACK_TYPE_ECDH_RESPONSE: //ignore
        //     return;
        case PACK_TYPE_PAIR_REQUEST: {
            wait_pair_pub_key = read_key_value(data_operator);
            if (data_operator.remaining() < 32) {
                Logger::e("AudioServer.handler_message", "invalid pair request: hmac too short. len=" + data_operator.remaining());
                return;
            }
            wait_pair_hmac = data_operator.get_array(32);
            pair_client = client;
            pair_timestamp = std::chrono::high_resolution_clock::now();
        }
        case PACK_TYPE_PAIR_COMPLETED: {
            if (!has_pair()) return;
            const auto client_pub_key = Crypto::ED25519::load_public_key_from_mem(wait_pair_pub_key);
            if (!client_pub_key.verify(ptr, data_operator.position(), data_operator.get_array(64))) {
                Logger::e("AudioServer.handler_message", "pair completed: sign verify failed. client name=" + client->key->name);
                return;
            }
            //TODO save pub key
        }
        //等待用户输入代码后再发送响应
        // case PACK_TYPE_PAIR_RESPONSE: //ignore
        case PACK_TYPE_AUDIO_START: //audio start
        {
            if (client == nullptr) {
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
            if (client == nullptr) {
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
            decrypted_data = decrypt(std::vector<uint8_t>(p_pack + 1, p_pack + length), client->session_key);
            // handle_message(addr, reinterpret_cast<const char *>(decrypted_data.data()),
            //                static_cast<int>(decrypted_data.size()), client, true);
            break;
        // case PACK_TYPE_SIGN_DATA:
        //     if (client == nullptr || client->key == nullptr) {
        //         Logger::e("AudioServer.handle_message", "invalid sign data: no sign public key");
        //         return;
        //     }
        //     if (!client->key->key.verify(std::vector<uint8_t>(p_pack, p_pack + length - 64),
        //                                  std::vector<uint8_t>(p_pack + length - 64, p_pack + length))) {
        //         Logger::e("AudioServer.handle_message",
        //                   "invalid pair request: sign verify failed. client name=" + client->key->name);
        //         return;
        //     }
        //     handle_message(addr, p_pack + 1, length - 65, client, false, true);
        //     break;
        default:
            Logger::e("AudioServer.handle_message", "unsupported pack type: " + std::to_string(p_pack[0]));
            break;
    }
}

bool AudioServer::pair(const std::string &code) {
    if (!has_pair()) return false;
    const auto key = Crypto::sha256(std::vector<uint8_t>(code.data(), code.data() + code.size()));
    if (const auto hmac = Crypto::hmac_sha256(key, wait_pair_pub_key); hmac != wait_pair_hmac) {
        clear_pair();
        Logger::e("AudioServer.handle_message", "pair failed: code error.");
        return false;
    }
    const auto pub_key = sign_key_pair.export_public_key();
    data_pack pack{AUDIO_SERVER_VERSION, PACK_TYPE_PAIR_RESPONSE, pub_key.size() + 64};
    pack.data_operator.put_array(pub_key);
    const auto hmac = Crypto::hmac_sha256(key, pub_key);
    pack.data_operator.put_array(hmac);
    send_to_client(pair_client, pack);
    return true;
}

void AudioServer::clear_pair() {
    pair_client = nullptr;
    pair_timestamp = std::chrono::high_resolution_clock::time_point();
    wait_pair_hmac = {};
    wait_pair_pub_key = {};
}

bool AudioServer::has_pair() {
    if (!pair_client || wait_pair_hmac.empty() || wait_pair_pub_key.empty()) return false;
    if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - pair_timestamp).count() > 60) {
        clear_pair();
        Logger::e("AudioServer.handle_message", "pair failed: timeout.");
        return false;
    }
    return true;
}
