//
// Created by bincker on 2025/6/29.
//
#include <cstring>
#include <filesystem>
#include <fstream>

#include "audio_server.h"
#include "../logger.h"
#include "openssl/rand.h"
#include "../exceptions.h"
#include "../data_operator.h"
#include "../tools/string.h"
#include "../tools/base64.h"

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

void AudioServer::start() {
    if (running) {
        running = false;
        if (accept_thread.joinable()) accept_thread.join();
    }
    running = true;
    accept_thread = std::thread(&AudioServer::accept_connections, this);
}


void AudioServer::init_client_key() {
    if (!std::filesystem::exists(CONFIG_PATH)) {
        if (!std::filesystem::create_directory(CONFIG_PATH)) {
            throw AudioException("failed to create config directory. dir=" + CONFIG_PATH.string());
        }
    }
    if (std::filesystem::exists(SIGN_KEY_FILE)) {
        sign_key_pair = Crypto::ED25519::load_private_key_from_file(SIGN_KEY_FILE.string());
    } else {
        sign_key_pair = Crypto::ED25519::generate();
        sign_key_pair.write_private_key_to_file(SIGN_KEY_FILE.string());
    }
    if (std::filesystem::exists(AUTHENTICATED_FILE)) {
        std::ifstream auth_file(AUTHENTICATED_FILE);
        std::string line;
        while (std::getline(auth_file, line)) {
            if (line.empty()) continue;
            const auto fields = string::split(line, ' ');
            if (fields.size() != 3) {
                Logger::w("AudioServer.Constructor", "invalid authenticated line: " + line);
                continue;
            }
            if (fields[0] == "ed25519") {
                client_keys[fields[2]] = key_info(
                    std::make_unique<Crypto::ED25519>(Crypto::ED25519::load_public_key_from_mem(Base64::decode(fields[1]))),
                    fields[2]
                );
            } else {
                Logger::w("AudioServer.Constructor", "unsupported crypto method: " + fields[0]);
            }
        }
    }
}

void AudioServer::add_client_key(key_info& key) {
    if (client_keys.contains(key.name)) {
        Logger::w("AudioServer.add_client_key", "key already exists");
        return;
    }
    std::ofstream auth_file(AUTHENTICATED_FILE, std::ios::app);
    auth_file << key.key->get_name() << " " << Base64::encode(key.key->export_public_key()) << " " << key.name << std::endl;
    client_keys[key.name] = std::move(key);
}

void AudioServer::delete_client_key(const key_info& key) {
    if (!client_keys.contains(key.name)) {
        Logger::w("AudioServer.add_client_key", "key not found: name=" + key.name);
        return;
    }

    std::ifstream auth_file(AUTHENTICATED_FILE);
    std::string line;
    std::string result_content;
    while (std::getline(auth_file, line)) {
        if (line.empty()) continue;
        const auto fields = string::split(line, ' ');
        if (fields.size() != 3) {
            Logger::w("AudioServer.Constructor", "invalid authenticated line: " + line);
            continue;
        }
        if (fields[2] != key.name) {
            result_content += line + "\n";
        }
    }
    auth_file.close();
    std::ofstream auth_file_out(AUTHENTICATED_FILE);
    auth_file_out << result_content;
    client_keys.erase(key.name);
}

void AudioServer::send_to_all(const data_pack &pack) const {
    std::lock_guard lock(const_cast<std::mutex&>(clients_mutex));
    for (const auto& client : clients) {
        if (!client.connected) continue;
        const auto result = send(client.socket_fd, reinterpret_cast<const char *>(pack.data.get()),
                                pack.data_operator.remaining(), 0);
        if ( result < 1 ) {
            Logger::e("AudioServer::send_to_all", "send failed: " + std::to_string(result));
        } else if (result < pack.data_operator.remaining()) {
            Logger::e("AudioServer::send_to_all", "not sent completely: " + std::to_string(result) + "/" + std::to_string(pack.data_operator.remaining()));
        }
    }
}

void AudioServer::send_to_client(const client_info& client, const data_pack &pack) const {
    if (!client.connected) {
        Logger::w("AudioServer::send_to_client", "client not connected");
        return;
    }
    if (!pack.data) {
        Logger::e("AudioServer::send_to_client", "data pack is empty");
        return;
    }
    Logger::d("AudioServer::send_to_client", "sending to client: data length = " + std::to_string(pack.data_operator.remaining()));
    const auto result = send(client.socket_fd, reinterpret_cast<const char *>(pack.data.get()),
                            static_cast<int>(pack.data_operator.capacity()), 0);
    if ( result < 1 ) {
        Logger::e("AudioServer::send_to_client", "send failed: " + std::to_string(result));
    } else if (result < pack.data_operator.remaining()) {
        Logger::e("AudioServer::send_to_client", "not sent completely: " + std::to_string(result) + "/" + std::to_string(pack.data_operator.remaining()));
    }
}

void AudioServer::send_encrypted(const client_info& client, const data_pack &pack) const {
    data_pack encrypted_pack(PACK_TYPE_ENCRYPTED_DATA,pack.data_operator.capacity() + 64);
    encrypted_pack.data_operator.put_array(encrypt(pack.data.get(), pack.data_operator.capacity(), client.session_key));
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

bool AudioServer::is_paired(const client_info& client) const {
    return client.ecdh_pub_key != nullptr && client.key != nullptr && client_keys.contains(client.key->name);
}

void AudioServer::handle_message(const sockaddr_storage &addr, const uint8_t* ptr, const size_t size, client_info& client) {
    if (size < 4) {
        Logger::e("AudioServer.handle_message", "invalid package size: " + std::to_string(size));
        return;
    }

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
    client.active_time = std::chrono::high_resolution_clock::now();

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
            const data_pack pack{PACK_TYPE_PONG, 0};
            send_to_client(client, pack);
            return;
        }
        case PACK_TYPE_PONG: //pong
            return;
        case PACK_TYPE_ECDH_REQUEST: {
            if (client.ecdh_pub_key != nullptr) {
                Logger::e("AudioServer.handle_message", "repeat ecdh. client name=" + client.key->name);
                return;
            }
            client.ecdh_pub_key = std::make_unique<Crypto::X25519>(Crypto::X25519::load_public_key_from_mem(read_key_value(data_operator)));
            const auto key = ecdh_key_pair.export_public_key();
            data_pack pack{PACK_TYPE_ECDH_RESPONSE, 1 + 16 + 2 + key.size()};
            auto salt = std::vector<uint8_t>(16);
            RAND_bytes(salt.data(), static_cast<int>(salt.size()));
            pack.data_operator.put_array(salt);
            client.session_key = ecdh_key_pair.derive_shared_secret(*client.ecdh_pub_key, salt);
            pack.data_operator.put_uint16(key.size());
            pack.data_operator.put_array(key.data(), key.size());
            send_to_client(client, pack);
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
            pair_client = &client;
            pair_timestamp = std::chrono::high_resolution_clock::now();
        }
        case PACK_TYPE_PAIR_COMPLETED: {
            if (!has_pair()) return;
            const auto client_pub_key = Crypto::ED25519::load_public_key_from_mem(wait_pair_pub_key);
            if (!client_pub_key.verify(ptr, data_operator.position(), data_operator.get_array(64))) {
                Logger::e("AudioServer.handler_message", "pair completed: sign verify failed. client name=" + client.key->name);
                clear_pair();
                return;
            }
            key_info key(std::make_unique<Crypto::ED25519>(client_pub_key), wait_pair_client_name);
            client.key = &key;
            add_client_key(key);
        }
        //等待用户输入代码后再发送响应
        // case PACK_TYPE_PAIR_RESPONSE: //ignore
        case PACK_TYPE_AUDIO_START: //audio start
        {
            if (!is_paired(client)) {
                Logger::e("AudioServer.handle_message", "unauthorized client control.");
                return;
            }
            client.play = true;
            data_pack pack{PACK_TYPE_AUDIO_INFO, sizeof(audio_info) + 1};
            std::vector<uint8_t> audio_info_pack(sizeof(audio_info) + 1);
            audio_info_pack[0] = PACK_TYPE_AUDIO_INFO;
            pack.data_operator.put_array(reinterpret_cast<const uint8_t *>(&audio_info), sizeof(audio_info));
            memcpy(&audio_info_pack[1], &audio_info, sizeof(audio_info));
            const auto encrypted_data = encrypt(audio_info_pack.data(), audio_info_pack.size(), client.session_key);
            char res[1 + encrypted_data.size() + 64];
            res[0] = PACK_TYPE_AUDIO_INFO;
            memcpy(res + 1, encrypted_data.data(), encrypted_data.size());
            const auto sign = sign_key_pair.sign(encrypted_data);
            memcpy(res + 1 + encrypted_data.size(), sign.data(), sign.size());
            send(client.socket_fd, res, 1 + encrypted_data.size() + 64, 0);
            break;
        }
        case PACK_TYPE_AUDIO_STOP: //audio stop
            client.play = false;
            break;
        case PACK_TYPE_AUDIO_DATA: //audio data ignore
            break;
        case PACK_TYPE_ENCRYPTED_DATA:
            if (client.session_key.empty()) {
                Logger::e("AudioServer.handle_message", "invalid sign data: no session key. ");
                return;
            }
            // decrypted_data = decrypt(std::vector<uint8_t>(p_pack + 1, p_pack + length), client->session_key);
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
            Logger::e("AudioServer.handle_message", "unsupported pack type: " + data_operator.to_hex());
            break;
    }
}

bool AudioServer::pair(const std::string &code, const std::string &name) {
    if (!has_pair()) return false;
    const auto key = Crypto::sha256(std::vector<uint8_t>(code.data(), code.data() + code.size()));
    if (const auto hmac = Crypto::hmac_sha256(key, wait_pair_pub_key); hmac != wait_pair_hmac) {
        clear_pair();
        Logger::e("AudioServer.handle_message", "pair failed: code error.");
        return false;
    }
    const auto pub_key = sign_key_pair.export_public_key();
    data_pack pack{PACK_TYPE_PAIR_RESPONSE, pub_key.size() + 64};
    pack.data_operator.put_array(pub_key);
    const auto hmac = Crypto::hmac_sha256(key, pub_key);
    pack.data_operator.put_array(hmac);
    send_to_client(*pair_client, pack);
    wait_pair_client_name = name;
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
