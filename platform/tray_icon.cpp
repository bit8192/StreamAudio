//
// Created by Claude on 2026/1/1.
//

#include "tray_icon.h"
#include <QAction>
#include <QIcon>
#include <QApplication>
#include "../logger.h"

constexpr char LOG_TAG[] = "TrayIcon";

TrayIcon::TrayIcon(const QString& icon_path, TrayMenuCallback callback, QObject* parent)
    : QObject(parent), menu_callback_(std::move(callback)) {

    // 创建托盘图标
    tray_icon_ = new QSystemTrayIcon(this);

    // 设置图标
    QIcon icon(icon_path);
    if (icon.isNull()) {
        Logger::w(LOG_TAG, "无法加载图标: " + icon_path.toStdString());
    }
    tray_icon_->setIcon(icon);

    // 创建右键菜单
    create_menu();

    // 连接信号
    connect(tray_icon_, &QSystemTrayIcon::activated,
            this, &TrayIcon::on_activated);

    Logger::i(LOG_TAG, "托盘图标已创建");
}

TrayIcon::~TrayIcon() {
    if (tray_icon_) {
        tray_icon_->hide();
    }
    Logger::i(LOG_TAG, "托盘图标已销毁");
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

    // 如果是退出，直接退出应用
    if (action_data == "quit") {
        QApplication::quit();
        return;
    }

    // 调用回调函数
    if (menu_callback_) {
        menu_callback_(action_data);
    }
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
