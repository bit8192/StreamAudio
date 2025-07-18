//
// Created by Bincker on 2025/6/25.
//

#ifndef STREAMSOUND_AUDIO_H
#define STREAMSOUND_AUDIO_H

#include <istream>
#ifdef _WIN32
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <functiondiscoverykeys.h>
#else
#include <pulse/simple.h>
#endif
#include <functional>
#include <cstdint>

#define REFTIMES_PER_SEC  10000000
#define REFTIMES_PER_MILLISEC  10000

#pragma pack(push, 1)
struct WAVEFILEHEADER {
    char riff[4] = {'R', 'I', 'F', 'F'};
    uint32_t riffSize;
    char wave[4] = {'W', 'A', 'V', 'E'};
    char fmt[4] = {'f', 'm', 't', ' '};
    uint32_t fmtSize = 16;
    uint16_t audioFormat;
    uint16_t numChannels;
    uint32_t sampleRate;
    uint32_t byteRate;
    uint16_t blockAlign;
    uint16_t bitsPerSample;
    char data[4] = {'d', 'a', 't', 'a'};
    uint32_t dataSize;
};
#pragma pack(pop)

struct audio_info {
    uint32_t sample_rate;
    uint16_t bits;
    uint16_t format;
    uint16_t channels;
};

class Audio {
private:
#ifdef _WIN32
    HRESULT hr;
    uint32_t bufferFrameCount = 0;
    uint32_t numFramesAvailable = 0;
    IMMDeviceEnumerator* pEnumerator = nullptr;
    IMMDevice* pDevice = nullptr;
    IAudioClient* pAudioClient = nullptr;
    IAudioCaptureClient* pCaptureClient = nullptr;
    unsigned int packetLength = 0;
    uint8_t* pData = nullptr;
    uint32_t flags = 0;
    WAVEFORMATEX *pwfx = nullptr;
#else
    pa_simple *pulse;
    int error = 0;
#endif

public:
    Audio();

    audio_info get_audio_info();

    void capture(const std::function<bool(const char *, uint32_t)> &callback);

    ~Audio();
};


#endif //STREAMSOUND_AUDIO_H
