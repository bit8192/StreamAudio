//
// Created by Bincker on 2025/6/25.
//

#ifndef STREAMSOUND_AUDIO_H
#define STREAMSOUND_AUDIO_H

#include <istream>
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <functiondiscoverykeys.h>
#include <functional>

#define REFTIMES_PER_SEC  10000000
#define REFTIMES_PER_MILLISEC  10000

#pragma pack(push, 1)
struct WAVEFILEHEADER {
    char riff[4] = { 'R', 'I', 'F', 'F' };
    DWORD riffSize;
    char wave[4] = { 'W', 'A', 'V', 'E' };
    char fmt[4] = { 'f', 'm', 't', ' ' };
    DWORD fmtSize = 16;
    WORD audioFormat;
    WORD numChannels;
    DWORD sampleRate;
    DWORD byteRate;
    WORD blockAlign;
    WORD bitsPerSample;
    char data[4] = { 'd', 'a', 't', 'a' };
    DWORD dataSize;
};
#pragma pack(pop)

class Audio {
private:
    HRESULT hr;
    REFERENCE_TIME hnsRequestedDuration = REFTIMES_PER_SEC;
    REFERENCE_TIME hnsActualDuration;
    UINT32 bufferFrameCount = 0;
    UINT32 numFramesAvailable = 0;
    IMMDeviceEnumerator* pEnumerator = nullptr;
    IMMDevice* pDevice = nullptr;
    IAudioClient* pAudioClient = nullptr;
    IAudioCaptureClient* pCaptureClient = nullptr;
    WAVEFORMATEX* pwfx = nullptr;
    unsigned int packetLength = 0;
    BYTE* pData = nullptr;
    DWORD flags = 0;
    void generateSilence(BYTE* buffer, UINT32 size);
public:
    Audio();

    const WAVEFORMATEX* getWaveFormat();

    void capture(const std::function<bool(const char *, UINT32)> &callback);

    ~Audio();

protected:
    int underflow();
};


#endif //STREAMSOUND_AUDIO_H
