//
// Created by Bincker on 2025/6/25.
//

#include "../audio.h"
#include "../../exceptions.h"


const CLSID CLSID_MMDeviceEnumerator = __uuidof(MMDeviceEnumerator);
const IID IID_IMMDeviceEnumerator = __uuidof(IMMDeviceEnumerator);
const IID IID_IAudioClient = __uuidof(IAudioClient);
const IID IID_IAudioCaptureClient = __uuidof(IAudioCaptureClient);

Audio::Audio() {
    // COM 初始化由 Qt 应用负责，不在此处重复初始化
    hr = CoCreateInstance(CLSID_MMDeviceEnumerator, nullptr, CLSCTX_ALL, IID_IMMDeviceEnumerator, (void**)&pEnumerator);
    if (FAILED(hr)) throw AudioException("create core instance failed.");

    hr = pEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &pDevice);
    if (FAILED(hr)) throw AudioException("get default audio endpoint failed.");

    hr = pDevice->Activate(IID_IAudioClient, CLSCTX_ALL, nullptr, (void**)&pAudioClient);
    if (FAILED(hr)) throw AudioException("active device failed.");

    hr = pAudioClient->GetMixFormat(&pwfx);
    if (FAILED(hr)) throw AudioException("get mix format failed.");

    // 确保格式为PCM或IEEE_FLOAT
    if (pwfx->wFormatTag != WAVE_FORMAT_PCM && pwfx->wFormatTag != WAVE_FORMAT_IEEE_FLOAT) {
        // 尝试转换为标准PCM格式
        auto* pNewFormat = (WAVEFORMATEX*)CoTaskMemAlloc(sizeof(WAVEFORMATEX));
        if (!pNewFormat) {
            hr = E_OUTOFMEMORY;
            throw AudioException("transform pcm format failed.");
        }

        pNewFormat->wFormatTag = WAVE_FORMAT_PCM;
        pNewFormat->nChannels = pwfx->nChannels;
        pNewFormat->nSamplesPerSec = pwfx->nSamplesPerSec;
        pNewFormat->wBitsPerSample = 16;
        pNewFormat->nBlockAlign = pNewFormat->nChannels * pNewFormat->wBitsPerSample / 8;
        pNewFormat->nAvgBytesPerSec = pNewFormat->nSamplesPerSec * pNewFormat->nBlockAlign;
        pNewFormat->cbSize = 0;

        CoTaskMemFree(pwfx);
        pwfx = pNewFormat;
    }

    // 修改Audio构造函数中的初始化逻辑
    REFERENCE_TIME hnsRequestedDuration = 50 * 10000; // 50ms (单位: 100纳秒)
    REFERENCE_TIME hnsMinDuration;
    hr = pAudioClient->GetDevicePeriod(nullptr, &hnsMinDuration); // 获取设备支持的最小周期

// 使用最小周期或50ms中的较大者
    REFERENCE_TIME hnsBufferDuration = (hnsRequestedDuration > hnsMinDuration)
                                       ? hnsRequestedDuration : hnsMinDuration;

    hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED,
                                  AUDCLNT_STREAMFLAGS_LOOPBACK,
                                  hnsBufferDuration,
                                  0,
                                  pwfx,
                                  nullptr);
    if (FAILED(hr)) throw AudioException("initialize audio client failed.");

    hr = pAudioClient->GetBufferSize(&bufferFrameCount);
    if (FAILED(hr)) throw AudioException("get audio client buffer size failed.");

    hr = pAudioClient->GetService(IID_IAudioCaptureClient, (void**)&pCaptureClient);
    if (FAILED(hr)) throw AudioException("get audio client service failed.");

    hr = pAudioClient->Start();
    if (FAILED(hr)) throw AudioException("start audio capture failed.");
}

void generateSilence(const WAVEFORMATEX* pwfx, BYTE *buffer, UINT32 size) {
    if (pwfx->wFormatTag == WAVE_FORMAT_IEEE_FLOAT) {
        // 浮点格式静音为0.0f
        auto* floatBuffer = reinterpret_cast<float*>(buffer);
        for (UINT32 i = 0; i < size / sizeof(float); i++) {
            floatBuffer[i] = 0.0f;
        }
    } else {
        // PCM格式静音为0
        memset(buffer, 0, size);
    }
}

audio_info Audio::get_audio_info() {
    return {
        static_cast<uint32_t>(pwfx->nSamplesPerSec),
        pwfx->wBitsPerSample,
        pwfx->wFormatTag,
        pwfx->nChannels,
    };
}

void Audio::capture(const std::function<bool(const char *, UINT32)> &callback) {
    bool is_continue = true;

    while (is_continue) {
        hr = pCaptureClient->GetNextPacketSize(&packetLength);
        if (FAILED(hr)) throw AudioException("get nextPacket failed.");

        while (packetLength != 0) {
            hr = pCaptureClient->GetBuffer(&pData, &numFramesAvailable, (DWORD*) &flags, nullptr, nullptr);
            if (FAILED(hr)) throw AudioException("get buffer failed.");

            DWORD bytesToWrite = numFramesAvailable * pwfx->nBlockAlign;

            if (flags & AUDCLNT_BUFFERFLAGS_SILENT) {
                // 写入静音数据
                std::vector<BYTE> silence(bytesToWrite);
                generateSilence(pwfx, silence.data(), bytesToWrite);
                is_continue = callback(reinterpret_cast<const char*>(silence.data()), bytesToWrite);
            } else {
                is_continue = callback(reinterpret_cast<const char *>(pData), bytesToWrite);
            }

            hr = pCaptureClient->ReleaseBuffer(numFramesAvailable);
            if (FAILED(hr)) throw AudioException("release buffer failed.");

            hr = pCaptureClient->GetNextPacketSize(&packetLength);
            if (FAILED(hr)) throw AudioException("get nextPacket failed.");
        }
    }
}

Audio::~Audio() {
    if (pCaptureClient) pCaptureClient->Release();
    if (pAudioClient) {
        pAudioClient->Stop();
        pAudioClient->Release();
    }
    if (pDevice) pDevice->Release();
    if (pEnumerator) pEnumerator->Release();
    if (pwfx) CoTaskMemFree(pwfx);
    // COM 反初始化由 Qt 应用负责
}
