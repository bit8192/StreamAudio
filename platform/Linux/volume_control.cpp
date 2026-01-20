#include "../volume_control.h"
#include <pulse/pulseaudio.h>
#include "../../logger.h"

constexpr char LOG_TAG[] = "VolumeControl";

VolumeControl::VolumeControl() {
    pa_mainloop = pa_mainloop_new();
    auto* ml_api = pa_mainloop_get_api(static_cast<::pa_mainloop*>(pa_mainloop));
    pa_context = pa_context_new(ml_api, "VolumeControl");

    if (pa_context_connect(static_cast<::pa_context*>(pa_context), nullptr, PA_CONTEXT_NOFLAGS, nullptr) < 0) {
        Logger::w(LOG_TAG, "无法连接 PulseAudio");
    }

    pa_context_state_t state;
    while ((state = pa_context_get_state(static_cast<::pa_context*>(pa_context))) != PA_CONTEXT_READY) {
        if (state == PA_CONTEXT_FAILED || state == PA_CONTEXT_TERMINATED) {
            Logger::w(LOG_TAG, "PulseAudio 连接失败");
            break;
        }
        pa_mainloop_iterate(static_cast<::pa_mainloop*>(pa_mainloop), 1, nullptr);
    }
}

void VolumeControl::mute() {
    if (!pa_context) return;

    auto* ctx = static_cast<::pa_context*>(pa_context);
    auto* ml = static_cast<::pa_mainloop*>(pa_mainloop);

    auto op = pa_context_get_sink_info_by_index(ctx, 0, [](::pa_context* c, const pa_sink_info* i, int eol, void* userdata) {
        if (eol || !i) return;
        auto* self = static_cast<VolumeControl*>(userdata);
        self->was_muted = i->mute;
        pa_context_set_sink_mute_by_index(c, i->index, 1, nullptr, nullptr);
    }, this);

    while (pa_operation_get_state(op) == PA_OPERATION_RUNNING) {
        pa_mainloop_iterate(ml, 1, nullptr);
    }
    pa_operation_unref(op);

    Logger::i(LOG_TAG, "系统已静音");
}

void VolumeControl::unmute() {
    if (!pa_context) return;

    auto* ctx = static_cast<::pa_context*>(pa_context);
    auto* ml = static_cast<::pa_mainloop*>(pa_mainloop);

    auto op = pa_context_get_sink_info_by_index(ctx, 0, [](::pa_context* c, const pa_sink_info* i, int eol, void* userdata) {
        if (eol || !i) return;
        auto* self = static_cast<VolumeControl*>(userdata);
        pa_context_set_sink_mute_by_index(c, i->index, self->was_muted ? 1 : 0, nullptr, nullptr);
    }, this);

    while (pa_operation_get_state(op) == PA_OPERATION_RUNNING) {
        pa_mainloop_iterate(ml, 1, nullptr);
    }
    pa_operation_unref(op);

    Logger::i(LOG_TAG, "系统静音已恢复");
}

VolumeControl::~VolumeControl() {
    if (pa_context) {
        pa_context_disconnect(static_cast<::pa_context*>(pa_context));
        pa_context_unref(static_cast<::pa_context*>(pa_context));
    }
    if (pa_mainloop) {
        pa_mainloop_free(static_cast<::pa_mainloop*>(pa_mainloop));
    }
}
