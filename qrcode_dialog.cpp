//
// Created by Claude on 2026/1/9.
//

#include "qrcode_dialog.h"
#include "tools/qrcodegen.h"
#include "logger.h"

#include <QVBoxLayout>
#include <QPainter>
#include <QImage>

constexpr char LOG_TAG[] = "QRCodeDialog";
constexpr int QR_MODULE_SIZE = 8;  // 每个模块的像素大小
constexpr int QR_BORDER = 4;       // 边框模块数

QRCodeDialog::QRCodeDialog(const QString& content, QWidget* parent)
    : QDialog(parent) {

    setWindowTitle("配对二维码");
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

    auto* layout = new QVBoxLayout(this);

    // 二维码显示标签
    qr_label_ = new QLabel(this);
    qr_label_->setAlignment(Qt::AlignCenter);
    layout->addWidget(qr_label_);

    // 内容显示标签
    content_label_ = new QLabel(this);
    content_label_->setAlignment(Qt::AlignCenter);
    content_label_->setWordWrap(true);
    content_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(content_label_);

    // 提示标签
    auto* hint_label = new QLabel("请使用 StreamAudio 客户端扫描二维码进行配对", this);
    hint_label->setAlignment(Qt::AlignCenter);
    hint_label->setStyleSheet("color: gray; font-size: 12px;");
    layout->addWidget(hint_label);

    setContent(content);
    setLayout(layout);

    // 设置固定大小
    setFixedSize(sizeHint());
}

void QRCodeDialog::setContent(const QString& content) {
    content_label_->setText(content);
    QPixmap qrPixmap = generateQRCode(content);
    if (!qrPixmap.isNull()) {
        qr_label_->setPixmap(qrPixmap);
    } else {
        qr_label_->setText("生成二维码失败");
    }
}

QPixmap QRCodeDialog::generateQRCode(const QString& content) {
    try {
        // 使用 qrcodegen 库生成二维码
        qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(
            content.toUtf8().constData(),
            qrcodegen::QrCode::Ecc::MEDIUM
        );

        int size = qr.getSize();
        int imageSize = (size + QR_BORDER * 2) * QR_MODULE_SIZE;

        // 创建图像
        QImage image(imageSize, imageSize, QImage::Format_RGB32);
        image.fill(Qt::white);

        QPainter painter(&image);
        painter.setPen(Qt::NoPen);
        painter.setBrush(Qt::black);

        // 绘制二维码模块
        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) {
                if (qr.getModule(x, y)) {
                    painter.drawRect(
                        (x + QR_BORDER) * QR_MODULE_SIZE,
                        (y + QR_BORDER) * QR_MODULE_SIZE,
                        QR_MODULE_SIZE,
                        QR_MODULE_SIZE
                    );
                }
            }
        }

        painter.end();

        Logger::i(LOG_TAG, "二维码生成成功: size=" + std::to_string(size));
        return QPixmap::fromImage(image);

    } catch (const qrcodegen::data_too_long& e) {
        Logger::e(LOG_TAG, "二维码数据过长: " + std::string(e.what()));
        return QPixmap();
    } catch (const std::exception& e) {
        Logger::e(LOG_TAG, "生成二维码失败: " + std::string(e.what()));
        return QPixmap();
    }
}
