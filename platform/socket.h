//
// Created by bincker on 2026/1/11.
//

#ifndef STREAMAUDIO_SOCKET_H
#define STREAMAUDIO_SOCKET_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
typedef SOCKET socket_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
typedef int socket_t;
constexpr socket_t INVALID_SOCKET = -1;
#endif

#endif //STREAMAUDIO_SOCKET_H