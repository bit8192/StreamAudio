//
// Created by OpenCode on 2026/1/21.
//

#ifndef STREAMAUDIO_MOVE_CLIENT_DIALOG_H
#define STREAMAUDIO_MOVE_CLIENT_DIALOG_H

#include <QDialog>
#include <QLabel>
#include <QPointer>
#include <QTcpServer>

class MoveClientDialog final : public QDialog {
    Q_OBJECT

public:
    explicit MoveClientDialog(QWidget* parent = nullptr);
    ~MoveClientDialog() override;

protected:
    void showEvent(QShowEvent* event) override;
    void closeEvent(QCloseEvent* event) override;

private:
    QLabel* qr_label_ = nullptr;
    QLabel* url_label_ = nullptr;
    QLabel* hint_label_ = nullptr;

    QTcpServer* server_ = nullptr;
    QString apk_path_;
    QString url_;

    bool start_http_server();
    void stop_http_server();
    void update_content();

    static QString find_apk_file();
    static QPixmap generate_qrcode(const QString& content);

private slots:
    void on_new_connection();
};

#endif //STREAMAUDIO_MOVE_CLIENT_DIALOG_H

