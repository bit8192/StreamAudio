#pragma once

class VolumeControl {
public:
    VolumeControl();
    void mute();
    void unmute();
    ~VolumeControl();

private:
#ifdef _WIN32
    void* pEndpointVolume = nullptr;
#else
    void* pa_context = nullptr;
    void* pa_mainloop = nullptr;
#endif
    bool was_muted = false;
};
