#include <cmath>
#include <iostream>
#include <ctime>
#include <fstream>
#include <thread>
#include <openssl/rand.h>

#include "platform/audio_server.h"
#include "platform/audio.h"
#include "tools/base64.h"
#include "tools/crypto.h"
#include "tools/string.h"


void WriteWaveHeader(std::ofstream &ofstream, const audio_info pwfx, uint32_t dataSize) {
    WAVEFILEHEADER header;

    header.audioFormat = pwfx.format;
    header.numChannels = pwfx.channels;
    header.sampleRate = pwfx.sample_rate;
    header.bitsPerSample = pwfx.bits;
    header.blockAlign = pwfx.channels * pwfx.bits / 8;
    header.byteRate = header.sampleRate * header.blockAlign;
    header.dataSize = dataSize;
    header.riffSize = dataSize + sizeof(header) - 8;

    ofstream.write(reinterpret_cast<const char *>(&header), sizeof(header));
}

void output_test(uint32_t times) {
    std::ofstream output("output.wav", std::ios::binary);
    auto start = std::time(nullptr);
    auto audio = Audio();

    auto headerPos = output.tellp();
    WriteWaveHeader(output, audio.get_audio_info(), 0);

    size_t size = 0;
    int i = 0;
    audio.capture([&start, &output, &size, &i, &times](auto data, auto len) {
        size += len;
        output.write(data, len);
        std::cout << i++ << ":\t" << len << std::endl;
        return std::time(nullptr) - start < times;
    });

    output.seekp(headerPos);
    WriteWaveHeader(output, audio.get_audio_info(), size);

    output.close();
}

void start_stream() {
    auto audio = Audio();
    auto server = AudioServer(8888, audio.get_audio_info());
    auto format = audio.get_audio_info();
    std::cout << "sample rate: " << format.sample_rate << std::endl;
    std::cout << "bit sample: " << format.bits << std::endl;
    std::cout << "format: " << format.format << std::endl;
    std::cout << "channel: " << format.channels << std::endl;
    server.start();
    bool running = true;
    // std::thread capture_thread([&server, &audio, &running, &format]() {
    //     while (running) {
    //         if(!server.wait_client(std::chrono::milliseconds(1000))) continue;
    //         std::cout << "client connected." << std::endl;
    //
    //         server.send_data(reinterpret_cast<const char *>(&format.sample_rate), 4);
    //         server.send_data(reinterpret_cast<const char *>(&format.bits), 2);
    //         server.send_data(reinterpret_cast<const char *>(&format.format), 2);
    //         server.send_data(reinterpret_cast<const char *>(&format.channels), 2);
    //
    //         audio.capture([&server, &running](auto data, auto len) {
    //             server.send_data(data, len);
    //             return running;
    //         });
    //         std::cout << "client lost." << std::endl;
    //     }
    // });
    while (running) {
        std::string cmd;
        std::getline(std::cin, cmd);
        if (cmd.starts_with("quit")) break;
        if (cmd.starts_with("pair")) {
            const auto param = string::split(cmd, ' ');
            if (param.size() != 3) {
                std::printf("invalid param. usage: pair <code> <name>\n");
                continue;
            }
            if (server.pair(param[1], param[2])) {
                std::printf("pair failed.\n");
            }else {
                std::printf("pair success.\n");
            }
        }
    }
    running = false;
    // capture_thread.join();
}

void test_crypto() {
    const Crypto::ED25519 signKeyPair = Crypto::ED25519::load_private_key_from_file("private_key.pem");
    // signKeyPair.write_private_key_to_file("private_key.pem");
    signKeyPair.write_public_key_to_file("public_key1.pem");
}

int main() {
    // output_test(10);
    start_stream();
    // test_crypto();
}
