#include <cmath>
#include <iostream>
#include <ctime>
#include <fstream>
#include <thread>
#include <openssl/rand.h>
#include <QApplication>
#include <QMessageBox>

#include "platform/audio_server.h"
#include "platform/audio.h"
#include "platform/config.h"
#include "platform/tray_icon.h"
#include "tools/crypto.h"
#include "tools/string.h"


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

void start_stream() {
    auto config = Config::load();
    auto audio = Audio();
    auto server = AudioServer(config.port, audio.get_audio_info());
    auto format = audio.get_audio_info();
    std::cout << "port: " << config.port << std::endl;
    std::cout << "sample rate: " << format.sample_rate << std::endl;
    std::cout << "bit sample: " << format.bits << std::endl;
    std::cout << "format: " << format.format << std::endl;
    std::cout << "channel: " << format.channels << std::endl;
    server.start();
    bool running = true;
    // std::thread capture_thread([&server, &audio, &running, &format]() {
    //     while (running) {
    //         if(!server.wait_client(std::chrono::milliseconds(1000))) continue;
    //         std::cout << "client connected." << std::endl;
    //
    //         server.send_data(reinterpret_cast<const char *>(&format.sample_rate), 4);
    //         server.send_data(reinterpret_cast<const char *>(&format.bits), 2);
    //         server.send_data(reinterpret_cast<const char *>(&format.format), 2);
    //         server.send_data(reinterpret_cast<const char *>(&format.channels), 2);
    //
    //         audio.capture([&server, &running](auto data, auto len) {
    //             server.send_data(data, len);
    //             return running;
    //         });
    //         std::cout << "client lost." << std::endl;
    //     }
    // });
    while (running) {
        std::string cmd;
        std::getline(std::cin, cmd);
        if (cmd.starts_with("quit")) break;
        if (cmd.starts_with("pair")) {
            const auto param = string::split(cmd, ' ');
            if (param.size() != 3) {
                std::printf("invalid param. usage: pair <code> <name>\n");
                continue;
            }
            if (server.pair(param[1], param[2])) {
                std::printf("pair failed.\n");
            }else {
                std::printf("pair success.\n");
            }
        }
    }
    running = false;
    // capture_thread.join();
}

void test_crypto() {
    const Crypto::ED25519 signKeyPair = Crypto::ED25519::load_private_key_from_file("private_key.pem");
    // signKeyPair.write_private_key_to_file("private_key.pem");
    signKeyPair.write_public_key_to_file("public_key1.pem");
}

int main(int argc, char *argv[]) {
    // 创建 Qt 应用
    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);

    // 加载配置
    auto config = Config::load();

    // 启动服务器线程
    std::thread server_thread([&config]() {
        auto audio = Audio();
        auto server = AudioServer(config.port, audio.get_audio_info());
        auto format = audio.get_audio_info();

        std::cout << "StreamSound 服务器已启动" << std::endl;
        std::cout << "端口: " << config.port << std::endl;
        std::cout << "采样率: " << format.sample_rate << std::endl;
        std::cout << "位深度: " << format.bits << std::endl;
        std::cout << "格式: " << format.format << std::endl;
        std::cout << "声道: " << format.channels << std::endl;

        server.start();

        // 保持服务器运行
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    // 定义托盘菜单回调
    auto menu_callback = [](const QString& action) {
        if (action == "pair_qrcode") {
            // TODO: 显示配对二维码
            QMessageBox::information(nullptr, "配对二维码",
                "配对二维码功能开发中...\n请使用命令行 pair 命令进行配对");
        } else if (action == "about") {
            QMessageBox::about(nullptr, "关于 StreamSound",
                "StreamSound v1.0\n\n"
                "跨平台音频流服务器\n"
                "支持 Windows 和 Linux\n\n"
                "使用 Qt、OpenSSL、PulseAudio/WASAPI 开发");
        }
    };

    // 创建托盘图标
    TrayIcon tray("icon.png", menu_callback);
    tray.set_tooltip(QString("StreamSound - 端口: %1").arg(config.port));
    tray.show();

    std::cout << "托盘图标已显示，右键查看菜单" << std::endl;

    // 运行 Qt 事件循环
    int ret = app.exec();

    // 注意：服务器线程会在程序退出时被强制终止
    // 如果需要优雅关闭，应该添加信号机制
    return ret;
}
