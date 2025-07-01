//
// Created by bincker on 2025/6/29.
//
#include "audio_server.h"

bool operator==(const sockaddr_in & lhs, const sockaddr_in & rhs) {
    if (lhs.sin_family != rhs.sin_family) return false;
    if (lhs.sin_port != rhs.sin_port) return false;
    if (lhs.sin_addr.s_addr != rhs.sin_addr.s_addr) return false;
    return true;
}

void AudioServer::handle_message(const sockaddr_in& client, const char* data, const int length) {
    if (length < 1) return;
    bool is_authenticated = false;
    for (auto [address, active_time] : clients) {
        if (address == client) {
            active_time = std::chrono::high_resolution_clock::now();
            is_authenticated = true;
            break;
        }
    }
    const char *res = nullptr;
    try{
        switch (data[0]) {
            case 0: //ping
                res = new char[]{1};
                sendto(server_socket, res, 1, 0, (sockaddr*) &client, sizeof(sockaddr_in));
                return;
            case 1: //pong
                return;
            case 2: //authentication request
                if (!is_authenticated) clients.emplace_back(client, std::chrono::high_resolution_clock::now());
                //todo send response
                return;
            case 3: //authentication response
                return;
            case 4: //pair request
                break;
            case 5: //pair response
                break;
            case 6: //audio start
                break;
            case 7: //audio stop
                break;
            case 8: //audio data
                break;
        }
        delete[] res;
    } catch (...) {
        delete[] res;
    }
}
