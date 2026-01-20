//
// Created by Bincker on 2025/6/25.
//

#include "../audio.h"
#include "../../config.h"

#include <pulse/error.h>
#include <pulse/pulseaudio.h>
#include <chrono>
#include <iostream>
#include <cstring>

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

    // 使用一个简单的结构体存储sink信息
    struct SinkInfo {
        std::string name;
        std::string monitor_source_name;
    };
    std::vector<SinkInfo> sinks;

    // 查询所有输出设备
    pa_operation *op = pa_context_get_sink_info_list(
        context, [](pa_context *context, const pa_sink_info *sink_info, int eol, void *sinks) {
            if (eol < 0) {
                std::string msg = "查询设备错误: ";
                msg += pa_strerror(pa_context_errno(context));
                throw AudioException(msg.c_str());
            }
            if (!sink_info) return;

            SinkInfo info;
            info.name = sink_info->name;
            info.monitor_source_name = sink_info->monitor_source_name;
            static_cast<std::vector<SinkInfo> *>(sinks)->push_back(info);
        }, &sinks);
    while (pa_operation_get_state(op) == PA_OPERATION_RUNNING) {
        pa_mainloop_iterate(ml, 1, nullptr);
    }
    pa_operation_unref(op);

    // 查询默认设备
    std::string default_sink_monitor_name;
    void *userdata[]{&sinks, &default_sink_monitor_name};
    op = pa_context_get_server_info(context, [](pa_context *, const pa_server_info *server_info, void *userdata) {
        if (server_info == nullptr) return;
        const auto ptrs = static_cast<void **>(userdata);
        const auto sinks = static_cast<std::vector<SinkInfo> *>(ptrs[0]);
        const auto default_sink_monitor_name = static_cast<std::string *>(ptrs[1]);

        for (const auto& sink: (*sinks)) {
            if (sink.name == server_info->default_sink_name) {
                *default_sink_monitor_name = sink.monitor_source_name;
                break;
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

    // 如果没有找到默认监控源，尝试使用nullptr让PulseAudio自动选择
    if (default_sink_monitor_name.empty()) {
        std::cerr << "Warning: No default monitor found, will try to use default source" << std::endl;
    }

    return default_sink_monitor_name;
}

pa_sample_spec ss;
uint32_t buffer_size;

Audio::Audio(const std::shared_ptr<Config>& config) {
    buffer_size = config->buffer_size;
    ss.format = config->bits == 16 ? PA_SAMPLE_S16LE : PA_SAMPLE_S32LE;
    ss.rate = config->sample_rate;
    ss.channels = config->channels;
    // 创建 PulseAudio 捕获流（监控音频输出）
    const auto default_sink_monitor_name = get_default_output_monitor();

    // 如果设备名为空，使用nullptr让PulseAudio自动选择
    const char* device_name = default_sink_monitor_name.empty() ? nullptr : default_sink_monitor_name.c_str();

    pa_buffer_attr buffer_attr = {
        .maxlength = buffer_size * 4,
        .tlength = (uint32_t) -1,
        .prebuf = (uint32_t) -1,
        .minreq = buffer_size,
        .fragsize = buffer_size
    };

    pulse = pa_simple_new(
        nullptr, // 默认服务器
        "StreamAudio", // 应用名
        PA_STREAM_RECORD, // 捕获模式
        device_name, // 设备名称（可以是nullptr）
        "Record", // 流描述
        &ss, // 采样格式
        nullptr, // 默认声道映射
        &buffer_attr, // 默认缓冲属性
        &error // 错误码
    );

    if (!pulse) {
        throw_exception("PulseAudio初始化错误: ", error);
    }
}

void Audio::capture(const std::function<bool(const char *, uint32_t)> &callback) {
    std::vector<uint8_t> buffer(buffer_size);
    bool is_continue = true;
    while (is_continue) {
        const auto len = pa_simple_read(pulse, buffer.data(), buffer.size(), &error);
        if (len < 0) {
            throw_exception("PulseAudio 读取错误: ", error);
        }
        is_continue = callback(reinterpret_cast<const char *>(buffer.data()), buffer_size);
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
