//
// Created by Bincker on 2025/6/26.
//

#include "../audio_server.h"

#include <filesystem>
#include <fstream>

#include "../../exceptions.h"
#include "../../logger.h"
#include "../../tools/string.h"
#include "../../tools/base64.h"
#include "../../tools/crypto.h"

constexpr auto AUDIO_SERVER_LOGTAG = "audio_server";
const std::string HOME_DIR = std::getenv("USERPROFILE");
const auto CONFIG_PATH = HOME_DIR + R"(\.config\stream-sound)";
const auto SIGN_KEY_FILE = CONFIG_PATH + "\\sign-key.pem";
const auto AUTHENTICATED_FILE = CONFIG_PATH + "\\sign-key.pem";

AudioServer::AudioServer(const int port, const struct audio_info &audio_info): ecdh_key_pair(X25519::generate()),
                                                                               sign_key_pair(ED25519::empty()),
                                                                               audio_info(audio_info) {
    if (!std::filesystem::exists(CONFIG_PATH)) {
        if (std::filesystem::create_directory(CONFIG_PATH)) {
            throw AudioException("Failed to create config directory");
        }
    }
    if (std::filesystem::exists(SIGN_KEY_FILE)) {
        sign_key_pair = ED25519::load_public_key_from_file(SIGN_KEY_FILE);
    } else {
        sign_key_pair = ED25519::generate();
        sign_key_pair.write_private_key_to_file(SIGN_KEY_FILE);
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
                client_keys.emplace_back(
                    fields[0],
                    ED25519::load_public_key_from_mem(Base64::decode(fields[1])),
                    fields[2]
                );
            } else {
                Logger::w("AudioServer.Constructor", "unsupported crypto method: " + fields[0]);
                continue;
            }
        }
    }
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        throw SocketException("socket init failed.");
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_UDP);
    if (server_socket == INVALID_SOCKET) {
        const auto error = "socket create failed. error=" + std::to_string(WSAGetLastError());
        throw SocketException(error.c_str());
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    if (bind(server_socket, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) == SOCKET_ERROR) {
        throw SocketException("bind failed");
    }
}

void AudioServer::start() {
    if (running) {
        running = false;
        if (server_thread.joinable()) server_thread.join();
    }
    running = true;
    server_thread = std::thread(&AudioServer::receive_data, this);
}

void AudioServer::receive_data() {
    char buffer[PACKAGE_SIZE];
    sockaddr_in client_addr{};
    int addr_len = sizeof(client_addr);
    while (running) {
        const int len = recvfrom(server_socket, buffer, PACKAGE_SIZE, 0, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);
        if (len == SOCKET_ERROR) {
            Logger::e(AUDIO_SERVER_LOGTAG, "receive data failed. status=" + len);
            continue;
        }
        try {
            handle_message(client_addr, buffer, len);
        } catch (const std::exception &e) {
            Logger::e(AUDIO_SERVER_LOGTAG, "handle message failed.", e);
        }
    }
}

void AudioServer::send_data(const char *data, const int size) const {
    for (const client_info& client: clients) {
        try {
            sendto(server_socket, data, size, 0, (sockaddr*) &client.address, sizeof(client.address));
        } catch (const SocketException &e) {
            Logger::e(AUDIO_SERVER_LOGTAG, "send data failed", e);
        }
    }
}

AudioServer::~AudioServer() {
    closesocket(server_socket);
}
