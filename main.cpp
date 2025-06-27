#include <iostream>
#include <ctime>
#include <fstream>
#include <thread>
#include "platform/audio_server.h"
#include "platform/audio.h"


void WriteWaveHeader(std::ofstream& ofstream, const WAVEFORMATEX* pwfx, DWORD dataSize) {
    WAVEFILEHEADER header;

    header.audioFormat = pwfx->wFormatTag;
    header.numChannels = pwfx->nChannels;
    header.sampleRate = pwfx->nSamplesPerSec;
    header.bitsPerSample = pwfx->wBitsPerSample;
    header.blockAlign = pwfx->nChannels * pwfx->wBitsPerSample / 8;
    header.byteRate = header.sampleRate * header.blockAlign;
    header.dataSize = dataSize;
    header.riffSize = dataSize + sizeof(header) - 8;

    ofstream.write(reinterpret_cast<const char *>(&header), sizeof(header));
}

void output_test(uint32_t times){
    std::ofstream output("output.wav", std::ios::binary);
    auto start = std::time(nullptr);
    auto audio = Audio();

    auto headerPos = output.tellp();
    WriteWaveHeader(output, audio.getWaveFormat(), 0);

    size_t size = 0;
    int i = 0;
    audio.capture([&start, &output, &size, &i, &times](auto data, auto len) {
        size += len;
        output.write(data, len);
        std::cout << i++ << ":\t" << len << std::endl;
        return std::time(nullptr) - start < times;
    });

    output.seekp(headerPos);
    WriteWaveHeader(output, audio.getWaveFormat(), size);

    output.close();
}

void start_stream() {
    auto audio = Audio();
    auto server = AudioServer("0.0.0.0", 8888);
    auto format = audio.getWaveFormat();
    std::cout << "sample rate: " << format->nSamplesPerSec << std::endl;
    std::cout << "bit sample: " << format->wBitsPerSample << std::endl;
    std::cout << "format: " << format->wFormatTag << std::endl;
    std::cout << "channel: " << format->nChannels << std::endl;
    server.start();
    bool running = true;
    std::thread capture_thread([&server, &audio, &running, &format](){
        while (running) {
            if(!server.wait_client(std::chrono::milliseconds(1000))) continue;
            std::cout << "client connected." << std::endl;

//            std::cout << "sampleRate: " <<
            server.send_data((const char *) &format->nSamplesPerSec, 4);
            server.send_data((const char *) &format->wBitsPerSample, 2);
            server.send_data((const char *) &format->wFormatTag, 2);
            server.send_data((const char *) &format->nChannels, 2);

            audio.capture([&server, &running](auto data, auto len){
                return server.send_data(data, len) && running;
            });
            std::cout << "client lost." << std::endl;
        }
    });
    while (running){
        std::string cmd;
        std::cin >> cmd;
        if (cmd.starts_with("quit")) break;
    }
    running = false;
    capture_thread.join();
}

int main(){
//    output_test(10);
    start_stream();
}
