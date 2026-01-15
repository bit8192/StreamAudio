//
// Created by Claude on 2026/1/9.
//

#ifndef STREAMAUDIO_QRCODE_DIALOG_H
#define STREAMAUDIO_QRCODE_DIALOG_H

#include <QDialog>
#include <QLabel>
#include <QString>

class QRCodeDialog : public QDialog {
    Q_OBJECT

public:
    explicit QRCodeDialog(const QString& content, QWidget* parent = nullptr);
    ~QRCodeDialog() override = default;

    void setContent(const QString& content);

private:
    QLabel* qr_label_;
    QLabel* content_label_;

    QPixmap generateQRCode(const QString& content);
};

#endif //STREAMAUDIO_QRCODE_DIALOG_H
