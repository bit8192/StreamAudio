#include <cmath>
#include <iostream>
#include <ctime>
#include <fstream>
#include <thread>
#include <openssl/rand.h>
#include <QApplication>

#include "logger.h"
#include "platform/audio_server.h"
#include "platform/audio.h"
#include "config.h"
#include "exceptions.h"
#include "platform/tray_icon.h"
#include "tools/crypto.h"
#include "tools/string.h"
#include "version.h"
#include "winsock_guard.h"


void WriteWaveHeader(std::ofstream &ofstream, const audio_info pwfx, uint32_t dataSize) {
    WAVEFILEHEADER header;

    header.audioFormat = pwfx.format;
    header.numChannels = pwfx.channels;
    header.sampleRate = pwfx.sample_rate;
    header.bitsPerSample = pwfx.bits;
    header.blockAlign = pwfx.channels * pwfx.bits / 8;
    header.byteRate = header.sampleRate * header.blockAlign;
    header.dataSize = dataSize;
    header.riffSize = dataSize + sizeof(header) - 8;

    ofstream.write(reinterpret_cast<const char *>(&header), sizeof(header));
}

void output_test(uint32_t times) {
    std::ofstream output("output.wav", std::ios::binary);
    auto start = std::time(nullptr);
    auto audio = Audio();

    auto headerPos = output.tellp();
    WriteWaveHeader(output, audio.get_audio_info(), 0);

    size_t size = 0;
    int i = 0;
    audio.capture([&start, &output, &size, &i, &times](auto data, auto len) {
        size += len;
        output.write(data, len);
        std::cout << i++ << ":\t" << len << std::endl;
        return std::time(nullptr) - start < times;
    });

    output.seekp(headerPos);
    WriteWaveHeader(output, audio.get_audio_info(), size);

    output.close();
}

void test_crypto() {
    const Crypto::ED25519 signKeyPair = Crypto::ED25519::load_private_key_from_file("private_key.pem");
    // signKeyPair.write_private_key_to_file("private_key.pem");
    signKeyPair.write_public_key_to_file("public_key1.pem");
}

constexpr char LOG_TAG[] = "Main";

int main(int argc, char *argv[]) {
#ifdef _WIN32
    // Windows: RAII 管理 Winsock 生命周期
    // 构造时初始化，析构时自动清理（无论正常退出还是异常退出）
    WinsockGuard winsock_guard;
#endif

    try {
        // 创建 Qt 应用
        QApplication app(argc, argv);
        QApplication::setQuitOnLastWindowClosed(false);
        // 加载配置
        const auto config = Config::load();

        // 创建音频服务器
        auto audio = Audio();
        const auto format = audio.get_audio_info();
        // 启动服务器
        const auto server = std::make_shared<AudioServer>(config.port, audio.get_audio_info());
        server->start();

        Logger::i("StreamSound 服务器已启动  version {}", VERSION_NAME);
        Logger::i(LOG_TAG, "端口: {}", config.port);
        Logger::i(LOG_TAG, "采样率: {}", format.sample_rate);
        Logger::i(LOG_TAG, "位深度: {}", format.bits);
        Logger::i(LOG_TAG, "格式: {}", format.format);
        Logger::i(LOG_TAG, "声道: {}", format.channels);

        // 创建托盘图标
        TrayIcon tray("icon.png", server);
        tray.show();

        // 运行 Qt 事件循环
        return QApplication::exec();
    } catch (AudioException &e) {
        Logger::e("音频服务启动失败", e.what());
        return 1;
    } catch (std::exception &e) {
        Logger::e("系统异常", e.what());
        return 1;
    } catch (...) {
        Logger::e("未知系统异常", "");
        return 1;
    }
}
