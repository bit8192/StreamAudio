#include "../volume_control.h"
#include <windows.h>
#include <mmdeviceapi.h>
#include <endpointvolume.h>
#include "../../logger.h"

constexpr char LOG_TAG[] = "VolumeControl";

VolumeControl::VolumeControl() {
}

void VolumeControl::mute() {
    // update_mute_state() may be invoked from different threads; COM must be initialized per-thread,
    // and the IAudioEndpointVolume interface shouldn't be cached cross-thread.
    auto hr = CoInitialize(nullptr);
    const bool com_should_uninit = (hr == S_OK || hr == S_FALSE);

    IMMDeviceEnumerator* pEnumerator = nullptr;
    IMMDevice* pDevice = nullptr;
    IAudioEndpointVolume* pVolume = nullptr;

    hr = CoCreateInstance(
        __uuidof(MMDeviceEnumerator),
        nullptr,
        CLSCTX_ALL,
        __uuidof(IMMDeviceEnumerator),
        reinterpret_cast<void**>(&pEnumerator)
    );
    if (FAILED(hr)) {
        Logger::w(LOG_TAG, "无法创建设备枚举器");
        goto cleanup;
    }

    hr = pEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &pDevice);
    if (FAILED(hr)) {
        Logger::w(LOG_TAG, "无法获取默认音频设备");
        goto cleanup;
    }

    hr = pDevice->Activate(__uuidof(IAudioEndpointVolume), CLSCTX_ALL, nullptr, reinterpret_cast<void**>(&pVolume));
    if (FAILED(hr) || !pVolume) {
        Logger::w(LOG_TAG, "无法激活音量控制接口");
        goto cleanup;
    }

    {
        BOOL muted = FALSE;
        if (SUCCEEDED(pVolume->GetMute(&muted))) {
            was_muted = (muted == TRUE);
        }
        pVolume->SetMute(TRUE, nullptr);
    }

    Logger::i(LOG_TAG, "系统已静音");

cleanup:
    if (pVolume) pVolume->Release();
    if (pDevice) pDevice->Release();
    if (pEnumerator) pEnumerator->Release();
    if (com_should_uninit) CoUninitialize();
}

void VolumeControl::unmute() {
    auto hr = CoInitialize(nullptr);
    const bool com_should_uninit = (hr == S_OK || hr == S_FALSE);

    IMMDeviceEnumerator* pEnumerator = nullptr;
    IMMDevice* pDevice = nullptr;
    IAudioEndpointVolume* pVolume = nullptr;

    hr = CoCreateInstance(
        __uuidof(MMDeviceEnumerator),
        nullptr,
        CLSCTX_ALL,
        __uuidof(IMMDeviceEnumerator),
        reinterpret_cast<void**>(&pEnumerator)
    );
    if (FAILED(hr)) {
        Logger::w(LOG_TAG, "无法创建设备枚举器");
        goto cleanup;
    }

    hr = pEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &pDevice);
    if (FAILED(hr)) {
        Logger::w(LOG_TAG, "无法获取默认音频设备");
        goto cleanup;
    }

    hr = pDevice->Activate(__uuidof(IAudioEndpointVolume), CLSCTX_ALL, nullptr, reinterpret_cast<void**>(&pVolume));
    if (FAILED(hr) || !pVolume) {
        Logger::w(LOG_TAG, "无法激活音量控制接口");
        goto cleanup;
    }

    pVolume->SetMute(was_muted ? TRUE : FALSE, nullptr);

    Logger::i(LOG_TAG, "系统静音已恢复");

cleanup:
    if (pVolume) pVolume->Release();
    if (pDevice) pDevice->Release();
    if (pEnumerator) pEnumerator->Release();
    if (com_should_uninit) CoUninitialize();
}

VolumeControl::~VolumeControl() {
}
