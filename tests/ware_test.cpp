//
// Created by bincker on 2026/1/14.
//

#include "../test_utils.h"
#include "../platform/audio.h"
#include <fstream>
#include <iostream>

namespace
{
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
        std::cout << "capture..." << std::endl;
        audio.capture([&start, &output, &size, &i, &times](auto data, auto len) {
            size += len;
            output.write(data, len);
            return std::time(nullptr) - start < times;
        });

        output.seekp(headerPos);
        WriteWaveHeader(output, audio.get_audio_info(), size);

        output.close();
    }
    TEST(ware_test)
    {
        output_test(10);
    }
}
