//
// Created by Bincker on 2025/6/25.
//

#include "../audio.h"
#include "../../exceptions.h"


const CLSID CLSID_MMDeviceEnumerator = __uuidof(MMDeviceEnumerator);
const IID IID_IMMDeviceEnumerator = __uuidof(IMMDeviceEnumerator);
const IID IID_IAudioClient = __uuidof(IAudioClient);
const IID IID_IAudioCaptureClient = __uuidof(IAudioCaptureClient);

HRESULT WriteWaveHeader(HANDLE hFile, WAVEFORMATEX* pwfx, DWORD dataSize) {
    WAVEFILEHEADER header;

    header.audioFormat = pwfx->wFormatTag;
    header.numChannels = pwfx->nChannels;
    header.sampleRate = pwfx->nSamplesPerSec;
    header.bitsPerSample = pwfx->wBitsPerSample;
    header.byteRate = pwfx->nSamplesPerSec * pwfx->nChannels * pwfx->wBitsPerSample / 8;
    header.blockAlign = pwfx->nChannels * pwfx->wBitsPerSample / 8;
    header.dataSize = dataSize;
    header.riffSize = dataSize + sizeof(header) - 8;

    DWORD written;
    return WriteFile(hFile, &header, sizeof(header), &written, nullptr) ? S_OK : E_FAIL;
}

Audio::Audio() {
    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) throw AudioException("core initialize failed.");

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

    hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED,
                                  AUDCLNT_STREAMFLAGS_LOOPBACK,
                                  hnsRequestedDuration,
                                  0,
                                  pwfx,
                                  nullptr);
    if (FAILED(hr)) throw AudioException("initialize audio client failed.");

    hr = pAudioClient->GetBufferSize(&bufferFrameCount);
    if (FAILED(hr)) throw AudioException("get audio client buffer size failed.");

    hr = pAudioClient->GetService(IID_IAudioCaptureClient, (void**)&pCaptureClient);
    if (FAILED(hr)) throw AudioException("get audio client service failed.");

    // 写入空的WAV文件头（稍后填充实际大小）
//    WriteWaveHeader(hFile, pwfx, 0);

    hnsActualDuration = (REFERENCE_TIME)((double)REFTIMES_PER_SEC * bufferFrameCount / pwfx->nSamplesPerSec);

    hr = pAudioClient->Start();
    if (FAILED(hr)) throw AudioException("start audio capture failed.");
}

void Audio::generateSilence(BYTE *buffer, UINT32 size) {
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

const WAVEFORMATEX *Audio::getWaveFormat() {
    return pwfx;
}

void Audio::capture(const std::function<bool(const char *, UINT32)> &callback) {
    bool isContinue = true;

    while (isContinue) {
        auto waitTime = static_cast<DWORD>(hnsActualDuration / REFTIMES_PER_MILLISEC / 2);
        if (waitTime < 1) waitTime = 1;

        Sleep(waitTime);

        hr = pCaptureClient->GetNextPacketSize(&packetLength);
        if (FAILED(hr)) throw AudioException("get nextPacket failed.");

        while (packetLength != 0) {
            hr = pCaptureClient->GetBuffer(&pData, &numFramesAvailable, &flags, nullptr, nullptr);
            if (FAILED(hr)) throw AudioException("get buffer failed.");

            DWORD bytesToWrite = numFramesAvailable * pwfx->nBlockAlign;

            if (flags & AUDCLNT_BUFFERFLAGS_SILENT) {
                // 写入静音数据
                std::vector<BYTE> silence(bytesToWrite);
                generateSilence(silence.data(), bytesToWrite);
                isContinue = callback(reinterpret_cast<const char*>(silence.data()), bytesToWrite);
            } else {
                isContinue = callback((const char *) pData, bytesToWrite);
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
    CoUninitialize();
}
