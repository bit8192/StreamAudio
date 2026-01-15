//
// Created by Claude on 2026/1/9.
//

#ifndef STREAMAUDIO_QRCODE_DIALOG_H
#define STREAMAUDIO_QRCODE_DIALOG_H

#include <QDialog>
#include <QLabel>
#include <QString>
#include <QVBoxLayout>

#include "platform/audio_server.h"

constexpr char MSG_HINT[] = "请使用 StreamAudio 客户端扫描二维码进行配对";
constexpr char MSG_QR_EXPIRED[] = "二维码已过期，点击刷新";
constexpr char MSG_QR_FAIL[] = "生成二维码失败";

class QRCodeDialog : public QDialog {
    Q_OBJECT

public:
    explicit QRCodeDialog(const std::shared_ptr<AudioServer> &audio_server, QWidget* parent = nullptr);
    ~QRCodeDialog() override = default;

protected:
    void showEvent(QShowEvent *) override;

    void hideEvent(QHideEvent *event) override;

    bool eventFilter(QObject *obj, QEvent *event) override;

private:
    QVBoxLayout* layout_;
    QLabel* qr_label_;
    QLabel* content_label_;
    QLabel* hint_label_;
    QTimer* timer_;
    std::shared_ptr<AudioServer> audio_server_;

    void setContent(const QString& content);

    QPixmap generateQRCode(const QString& content);

    void refresh();

    void clear_pair_code() const;

    void expire_pair_code() const;
};

#endif //STREAMAUDIO_QRCODE_DIALOG_H
