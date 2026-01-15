#include <fstream>
#include <thread>
#include <QApplication>

#include "logger.h"
#include "platform/audio_server.h"
#include "platform/audio.h"
#include "config.h"
#include "exceptions.h"
#include "tray_icon.h"
#include "version.h"
#include "platform/Windows/winsock_guard.h"

constexpr char LOG_TAG[] = "Main";
int main(int argc, char *argv[]) {
    WIN_SOCKET_GUARD_INIT()

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
        const auto server = std::make_shared<AudioServer>(config.port, audio.get_audio_info(), config.private_key);
        server->start();

        Logger::i("StreamAudio 服务器已启动  version {}", VERSION_NAME);
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
