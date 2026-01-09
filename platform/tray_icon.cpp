//
// Created by Claude on 2026/1/1.
//

#include "tray_icon.h"
#include "audio_server.h"
#include "qrcode_dialog.h"
#include "platform_utils.h"
#include <QAction>
#include <QIcon>
#include <QApplication>
#include <QMessageBox>
#include "../logger.h"

constexpr char LOG_TAG[] = "TrayIcon";

TrayIcon::TrayIcon(const QString& icon_path, std::shared_ptr<AudioServer> server, QObject* parent)
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
        tray_icon_->setToolTip(QString("StreamSound - 端口: %1").arg(server_->get_port()));
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
    QAction* pair_action = context_menu_->addAction("配对二维码");
    pair_action->setData("pair_qrcode");

    // 添加菜单项：关于
    QAction* about_action = context_menu_->addAction("关于");
    about_action->setData("about");

    // 添加分隔线
    context_menu_->addSeparator();

    // 添加退出菜单项
    QAction* quit_action = context_menu_->addAction("退出");
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

void TrayIcon::set_tooltip(const QString& tooltip) {
    if (tray_icon_) {
        tray_icon_->setToolTip(tooltip);
    }
}

void TrayIcon::update_icon(const QString& icon_path) {
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

void TrayIcon::on_menu_triggered(QAction* action) {
    if (!action) return;

    QString action_data = action->data().toString();
    Logger::i(LOG_TAG, "菜单项被点击: " + action_data.toStdString());

    if (action_data == "quit") {
        QApplication::quit();
    } else if (action_data == "pair_qrcode") {
        show_pair_qrcode();
    } else if (action_data == "about") {
        show_about();
    }
}

void TrayIcon::show_pair_qrcode() {
    if (!server_) {
        Logger::e(LOG_TAG, "AudioServer 未设置");
        QMessageBox::warning(nullptr, "错误", "服务器未初始化");
        return;
    }

    // 生成配对码
    std::string pairCode = server_->generate_pair_code();

    // 获取本机 IP 地址
    std::string ipAddress = PlatformUtils::get_preferred_ip_address();
    int port = server_->get_port();

    // 构造二维码内容: streamsound://PairCode@IP:Port
    QString qrContent = QString("streamsound://%1@%2:%3")
        .arg(QString::fromStdString(pairCode))
        .arg(QString::fromStdString(ipAddress))
        .arg(port);

    // 显示二维码对话框
    if (qr_dialog_) {
        qr_dialog_->setContent(qrContent);
        qr_dialog_->show();
        qr_dialog_->raise();
        qr_dialog_->activateWindow();
    } else {
        qr_dialog_ = new QRCodeDialog(qrContent);
        qr_dialog_->setAttribute(Qt::WA_DeleteOnClose);
        connect(qr_dialog_, &QDialog::destroyed, this, [this]() {
            qr_dialog_ = nullptr;
        });
        qr_dialog_->show();
    }

    Logger::i(LOG_TAG, "显示配对二维码: " + qrContent.toStdString());
}

void TrayIcon::show_about() {
    QMessageBox::about(nullptr, "关于 StreamSound",
        "StreamSound v1.0\n\n"
        "跨平台音频流服务器\n"
        "支持 Windows 和 Linux\n\n"
        "使用 Qt、OpenSSL、PulseAudio/WASAPI 开发");
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
