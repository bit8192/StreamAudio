#include "../volume_control.h"
#include <windows.h>
#include <mmdeviceapi.h>
#include <endpointvolume.h>
#include "../../logger.h"

constexpr char LOG_TAG[] = "VolumeControl";

VolumeControl::VolumeControl() {
    CoInitialize(nullptr);

    IMMDeviceEnumerator* pEnumerator = nullptr;
    IMMDevice* pDevice = nullptr;

    auto hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL, __uuidof(IMMDeviceEnumerator), (void**)&pEnumerator);
    if (FAILED(hr)) {
        Logger::w(LOG_TAG, "无法创建设备枚举器");
        return;
    }

    hr = pEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &pDevice);
    if (FAILED(hr)) {
        pEnumerator->Release();
        Logger::w(LOG_TAG, "无法获取默认音频设备");
        return;
    }

    hr = pDevice->Activate(__uuidof(IAudioEndpointVolume), CLSCTX_ALL, nullptr, &pEndpointVolume);
    pDevice->Release();
    pEnumerator->Release();

    if (FAILED(hr)) {
        Logger::w(LOG_TAG, "无法激活音量控制接口");
    }
}

void VolumeControl::mute() {
    if (!pEndpointVolume) return;

    auto* pVolume = static_cast<IAudioEndpointVolume*>(pEndpointVolume);
    BOOL muted;
    pVolume->GetMute(&muted);
    was_muted = muted;
    pVolume->SetMute(TRUE, nullptr);

    Logger::i(LOG_TAG, "系统已静音");
}

void VolumeControl::unmute() {
    if (!pEndpointVolume) return;

    auto* pVolume = static_cast<IAudioEndpointVolume*>(pEndpointVolume);
    pVolume->SetMute(was_muted ? TRUE : FALSE, nullptr);

    Logger::i(LOG_TAG, "系统静音已恢复");
}

VolumeControl::~VolumeControl() {
    if (pEndpointVolume) {
        static_cast<IAudioEndpointVolume*>(pEndpointVolume)->Release();
    }
    CoUninitialize();
}
