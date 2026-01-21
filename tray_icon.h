//
// Created by Claude on 2026/1/1.
//

#ifndef STREAMAUDIO_TRAY_ICON_H
#define STREAMAUDIO_TRAY_ICON_H

#include <QSystemTrayIcon>
#include <QMenu>
#include <QObject>
#include <memory>

class AudioServer;
class QRCodeDialog;
class MoveClientDialog;

class TrayIcon : public QObject {
    Q_OBJECT

public:
    explicit TrayIcon(const QString& icon_path, std::shared_ptr<AudioServer> server, QObject* parent = nullptr);
    ~TrayIcon() override;

    void show();
    void hide();
    void update_icon(const QString& icon_path);
    void set_tooltip(const QString& tooltip);

    [[nodiscard]] int get_port() const;

private slots:
    void on_menu_triggered(QAction* action);
    void on_activated(QSystemTrayIcon::ActivationReason reason);

private:
    QSystemTrayIcon* tray_icon_;
    QMenu* context_menu_;
    std::shared_ptr<AudioServer> server_;
    QRCodeDialog* qr_dialog_ = nullptr;
    MoveClientDialog* move_client_dialog_ = nullptr;

    void create_menu();
    void show_pair_qrcode();
    void show_move_client();
    void show_about();
};

#endif //STREAMAUDIO_TRAY_ICON_H
