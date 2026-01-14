//
// Created by Bincker on 2025/6/25.
//

#include "../audio.h"

#include <pulse/error.h>
#include <pulse/pulseaudio.h>
#include <chrono>
#include <iostream>

#include "../../exceptions.h"



void throw_exception(std::string msg, const int error) {
    msg += pa_strerror(error);
    throw AudioException(msg.c_str());
}

std::string get_default_output_monitor() {
    // 创建 PulseAudio 主循环和上下文
    pa_mainloop *ml = pa_mainloop_new();
    pa_mainloop_api *ml_api = pa_mainloop_get_api(ml);
    pa_context *context = pa_context_new(ml_api, "QueryDevice");

    // 连接 PulseAudio 服务器
    if (pa_context_connect(context, nullptr, PA_CONTEXT_NOFLAGS, nullptr) < 0) {
        throw AudioException("连接 PulseAudio 失败");
    }

    // 等待连接完成
    pa_context_state_t state;
    while ((state = pa_context_get_state(context)) != PA_CONTEXT_READY) {
        if (state == PA_CONTEXT_FAILED || state == PA_CONTEXT_TERMINATED) {
            throw AudioException("PulseAudio 连接错误");
        }
        pa_mainloop_iterate(ml, 1, nullptr); // 处理事件
    }

    // 查询所有输出设备
    std::vector<pa_sink_info> sinks;
    pa_operation *op = pa_context_get_sink_info_list(
        context, [](pa_context *context, const pa_sink_info *sink_info, int eol, void *sinks) {
            if (eol < 0) {
                std::string msg = "查询设备错误: ";
                msg += pa_strerror(pa_context_errno(context));
                throw AudioException(msg.c_str());
            }
            if (!sink_info) return;
            static_cast<std::vector<pa_sink_info> *>(sinks)->push_back(*sink_info);
        }, &sinks);
    while (pa_operation_get_state(op) == PA_OPERATION_RUNNING) {
        pa_mainloop_iterate(ml, 1, nullptr);
    }
    pa_operation_unref(op);

    // 查询设备
    std::string default_sink_monitor_name;
    void *userdata[]{&sinks, &default_sink_monitor_name};
    op = pa_context_get_server_info(context, [](pa_context *, const pa_server_info *server_info, void *userdata) {
        if (server_info == nullptr) return;
        const auto ptrs = static_cast<void **>(userdata);
        const auto sinks = static_cast<std::vector<pa_sink_info> *>(ptrs[0]);
        const auto default_sink_monitor_name = static_cast<std::string *>(ptrs[1]);
        for (auto sink: (*sinks)) {
            if (sink.name == std::string(server_info->default_sink_name)) {
                *default_sink_monitor_name = std::string(sink.monitor_source_name);
            }
        }
    }, &userdata);
    while (pa_operation_get_state(op) == PA_OPERATION_RUNNING) {
        pa_mainloop_iterate(ml, 1, nullptr);
    }
    pa_operation_unref(op);

    // 清理资源
    pa_context_disconnect(context);
    pa_context_unref(context);
    pa_mainloop_free(ml);

    return default_sink_monitor_name;
}

constexpr int BUFFER_SIZE = 1024;
// PulseAudio 配置
const pa_sample_spec ss = {
    .format = PA_SAMPLE_S16LE, // 16-bit signed little-endian
    .rate = 44100, // 采样率 (Hz)
    .channels = 2 // 立体声
};

Audio::Audio() {
    // 创建 PulseAudio 捕获流（监控音频输出）
    const auto default_sink_monitor_name = get_default_output_monitor();

    pa_buffer_attr buffer_attr = {
        .maxlength = 4 * 1024,
        .tlength = (uint32_t) -1,  // 目标缓冲区长度
        .prebuf = (uint32_t) -1,
        .minreq = BUFFER_SIZE,       // 最小请求大小
        .fragsize = BUFFER_SIZE      // 片段大小
    };

    pulse = pa_simple_new(
        nullptr, // 默认服务器
        "AudioCapture", // 应用名
        PA_STREAM_RECORD, // 捕获模式
        default_sink_monitor_name.c_str(),
        "Record", // 流描述
        &ss, // 采样格式
        nullptr, // 默认声道映射
        &buffer_attr, // 默认缓冲属性
        &error // 错误码
    );

    if (!pulse) throw_exception("PulseAudio 错误: ", error);
}

void Audio::capture(const std::function<bool(const char *, uint32_t)> &callback) {
    uint8_t buffer[BUFFER_SIZE];
    bool is_continue = true;
    while (is_continue) {
        const auto len = pa_simple_read(pulse, buffer, sizeof(buffer), &error);
        if (len < 0) {
            throw_exception("PulseAudio 读取错误: ", error);
        }
        is_continue = callback(reinterpret_cast<const char *>(buffer), BUFFER_SIZE);
    }
}

audio_info Audio::get_audio_info() {
    uint16_t bits = 0;
    if (ss.format == PA_SAMPLE_S16LE) {
        bits = 16;
    }else if (ss.format == PA_SAMPLE_S32LE) {
        bits = 32;
    }else throw AudioException("unsupported bits");
    uint16_t format = 1;
    if (ss.format != PA_SAMPLE_S16LE) throw AudioException("unsupported format");
    return {
        ss.rate,
        bits,
        format,
        ss.channels
    };
}


Audio::~Audio() {
    pa_simple_free(pulse);
}
