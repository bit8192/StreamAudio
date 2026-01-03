//
// Created by Claude on 2026/1/1.
//

#ifndef STREAMSOUND_TRAY_ICON_H
#define STREAMSOUND_TRAY_ICON_H

#include <QSystemTrayIcon>
#include <QMenu>
#include <QObject>
#include <functional>

// 菜单项回调函数类型
using TrayMenuCallback = std::function<void(const QString&)>;

class TrayIcon : public QObject {
    Q_OBJECT

public:
    explicit TrayIcon(const QString& icon_path, TrayMenuCallback callback, QObject* parent = nullptr);
    ~TrayIcon() override;

    // 显示托盘图标
    void show();

    // 隐藏托盘图标
    void hide();

    // 设置提示文本
    void set_tooltip(const QString& tooltip);

    // 更新图标
    void update_icon(const QString& icon_path);

private slots:
    void on_menu_triggered(QAction* action);
    void on_activated(QSystemTrayIcon::ActivationReason reason);

private:
    QSystemTrayIcon* tray_icon_;
    QMenu* context_menu_;
    TrayMenuCallback menu_callback_;

    void create_menu();
};

#endif //STREAMSOUND_TRAY_ICON_H
