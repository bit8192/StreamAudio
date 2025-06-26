#include <iostream>
#include <ctime>
#include <fstream>
#include <thread>
#include "platform/audio.h"
#include "platform/audio_server.h"


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

void test(){
    std::ofstream output("output.wav", std::ios::binary);
    auto start = std::time(nullptr);
    auto audio = Audio();

    auto headerPos = output.tellp();
    WriteWaveHeader(output, audio.getWaveFormat(), 0);

    size_t size = 0;
    int i = 0;
    audio.capture([&start, &output, &size, &i](auto data, auto len) {
        size += len;
        output.write(data, len);
        std::cout << i++ << ":\t" << len << std::endl;
        return std::time(nullptr) - start < 5;
    });

    output.seekp(headerPos);
    WriteWaveHeader(output, audio.getWaveFormat(), size);

    output.close();
}

int main() {
    auto audio = Audio();
    auto server = AudioServer("0.0.0.0", 8888);
    bool running = true;
    std::thread capture_thread([&server, &audio, &running](){
        audio.capture([&server, &running](auto data, auto len){
            server.send_data(data, len);
            return running;
        });
    });
    while (running){
        std::string cmd;
        std::cin >> cmd;
        if (cmd == "quit") break;
    }
    running = false;
    capture_thread.join();
    return 0;
}
