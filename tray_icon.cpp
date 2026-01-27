//
// Created by Claude on 2026/1/1.
//

#include "tray_icon.h"
#include "platform/audio_server.h"
#include "qrcode_dialog.h"
#include "move_client_dialog.h"
#include "platform_utils.h"
#include "config.h"
#include "version.h"
#include <QAction>
#include <QIcon>
#include <QApplication>
#include <QDesktopServices>
#include <QMessageBox>
#include <QUrl>
#include <QLabel>
#include "logger.h"

constexpr char LOG_TAG[] = "TrayIcon";

TrayIcon::TrayIcon(const QString &icon_path, std::shared_ptr<AudioServer> server, QObject *parent)
    : QObject(parent), server_(std::move(server)) {
    tray_icon_ = new QSystemTrayIcon(this);

    QIcon icon(icon_path);
    if (icon.isNull()) {
        Logger::w(LOG_TAG, "无法加载图标: " + icon_path.toStdString());
    }
    tray_icon_->setIcon(icon);

    create_menu();

    connect(tray_icon_, &QSystemTrayIcon::activated,
            this, &TrayIcon::on_activated);

    // 设置默认 tooltip
    if (server_) {
        tray_icon_->setToolTip(QString("StreamAudio - 端口: %1").arg(server_->get_port()));
    }

    Logger::i(LOG_TAG, "托盘图标已创建");
}

TrayIcon::~TrayIcon() {
    if (tray_icon_) {
        tray_icon_->hide();
    }
    Logger::i(LOG_TAG, "托盘图标已销毁");
}

int TrayIcon::get_port() const {
    return server_ ? server_->get_port() : 0;
}

void TrayIcon::create_menu() {
    context_menu_ = new QMenu();

    // 添加菜单项：配对二维码
    QAction *pair_action = context_menu_->addAction("配对二维码");
    pair_action->setData("pair_qrcode");

    // 添加菜单项：移动客户端
    QAction *move_action = context_menu_->addAction("移动客户端");
    move_action->setData("move_client");

    // 添加菜单项：开机启动（可勾选）
    QAction *autostart_action = context_menu_->addAction("开机启动");
    autostart_action->setData("auto_start");
    autostart_action->setCheckable(true);
    autostart_action->setChecked(PlatformUtils::is_auto_start_enabled());

    // 添加菜单项：配置文件
    QAction *config_action = context_menu_->addAction("配置文件");
    config_action->setData("config_file");

    // 添加菜单项：关于
    QAction *about_action = context_menu_->addAction("关于");
    about_action->setData("about");

    // 添加分隔线
    context_menu_->addSeparator();

    // 添加退出菜单项
    QAction *quit_action = context_menu_->addAction("退出");
    quit_action->setData("quit");

    // 连接菜单触发信号
    connect(context_menu_, &QMenu::triggered,
            this, &TrayIcon::on_menu_triggered);

    // 设置托盘图标的右键菜单
    tray_icon_->setContextMenu(context_menu_);
}

void TrayIcon::show() {
    if (tray_icon_) {
        tray_icon_->show();
        Logger::i(LOG_TAG, "托盘图标已显示");
    }
}

void TrayIcon::hide() {
    if (tray_icon_) {
        tray_icon_->hide();
        Logger::i(LOG_TAG, "托盘图标已隐藏");
    }
}

void TrayIcon::set_tooltip(const QString &tooltip) {
    if (tray_icon_) {
        tray_icon_->setToolTip(tooltip);
    }
}

void TrayIcon::update_icon(const QString &icon_path) {
    if (tray_icon_) {
        QIcon icon(icon_path);
        if (!icon.isNull()) {
            tray_icon_->setIcon(icon);
            Logger::i(LOG_TAG, "图标已更新: " + icon_path.toStdString());
        } else {
            Logger::w(LOG_TAG, "无法加载新图标: " + icon_path.toStdString());
        }
    }
}

void TrayIcon::on_menu_triggered(QAction *action) {
    if (!action) return;

    QString action_data = action->data().toString();
    Logger::i(LOG_TAG, "菜单项被点击: " + action_data.toStdString());

    if (action_data == "quit") {
        QApplication::quit();
    } else if (action_data == "pair_qrcode") {
        show_pair_qrcode();
    } else if (action_data == "move_client") {
        show_move_client();
    } else if (action_data == "auto_start") {
        const bool enabled = action->isChecked();
        std::string err;
        if (!PlatformUtils::set_auto_start_enabled(enabled, &err)) {
            Logger::e(LOG_TAG, "set auto start failed: " + err);
            QMessageBox::warning(nullptr, "错误", "设置开机启动失败");
            action->setChecked(!enabled);
        }
    } else if (action_data == "config_file") {
        const auto path = Config::get_config_file_path();
        const QString file_path = QString::fromStdString(path.string());
        if (!QDesktopServices::openUrl(QUrl::fromLocalFile(file_path))) {
            QMessageBox::warning(nullptr, "错误", "无法使用默认程序打开配置文件");
        }
    } else if (action_data == "about") {
        show_about();
    }
}

void TrayIcon::show_move_client() {
    if (move_client_dialog_ == nullptr) {
        move_client_dialog_ = new MoveClientDialog();
        move_client_dialog_->setAttribute(Qt::WA_DeleteOnClose);
        connect(move_client_dialog_, &QDialog::destroyed, this, [this] {
            move_client_dialog_ = nullptr;
        });
    }
    move_client_dialog_->show();
}

void TrayIcon::show_pair_qrcode() {
    if (!server_) {
        Logger::e(LOG_TAG, "AudioServer 未设置");
        QMessageBox::warning(nullptr, "错误", "服务器未初始化");
        return;
    }
    if (!server_->get_pair_code().empty()) {
        Logger::w(LOG_TAG, "配对未完成");
        return;
    }
    // 显示二维码对话框
    if (qr_dialog_ == nullptr) {
        qr_dialog_ = new QRCodeDialog(server_);
        qr_dialog_->setAttribute(Qt::WA_DeleteOnClose);
        connect(qr_dialog_, &QDialog::destroyed, this, [this] {
            qr_dialog_ = nullptr;
        });
    }
    qr_dialog_->show();
}

void TrayIcon::show_about() {
    QMessageBox about_box;
    about_box.setWindowTitle("关于 StreamAudio");
    about_box.setTextFormat(Qt::RichText);
    about_box.setTextInteractionFlags(Qt::TextBrowserInteraction);
    const QString about_text = QString(
        "<p>"
        "StreamAudio v%1<br><br>"
        "跨平台音频流服务器<br>"
        "支持 Windows 和 Linux<br><br>"
        "作者：bincker (<a href=\"mailto:bit16@qq.com\">bit16@qq.com</a>)<br>"
        "源码地址：<a href=\"https://github.com/bit8192/StreamAudio\">"
        "https://github.com/bit8192/StreamAudio</a><br><br>"
        "开源协议：GPL-3.0<br>"
        "<a href=\"https://github.com/bit8192/StreamAudio/blob/main/LICENSE\">"
        "https://github.com/bit8192/StreamAudio/blob/main/LICENSE</a><br><br>"
        "使用 Qt、OpenSSL、PulseAudio/WASAPI 开发"
        "</p>"
    ).arg(VERSION_NAME);
    about_box.setText(about_text);
    if (auto *label = about_box.findChild<QLabel*>("qt_msgbox_label")) {
        label->setOpenExternalLinks(true);
    }
    about_box.exec();
}

void TrayIcon::on_activated(QSystemTrayIcon::ActivationReason reason) {
    switch (reason) {
        case QSystemTrayIcon::Trigger:
            // 单击托盘图标
            Logger::d(LOG_TAG, "托盘图标被单击");
            break;
        case QSystemTrayIcon::DoubleClick:
            // 双击托盘图标
            Logger::d(LOG_TAG, "托盘图标被双击");
            break;
        case QSystemTrayIcon::MiddleClick:
            // 中键点击
            Logger::d(LOG_TAG, "托盘图标被中键点击");
            break;
        default:
            break;
    }
}
