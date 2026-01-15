//
// Created by Claude on 2026/1/9.
//

#include "qrcode_dialog.h"
#include "tools/qrcodegen.h"
#include "logger.h"

#include <QVBoxLayout>
#include <QPainter>
#include <QImage>
#include <QTimer>
#include <QMouseEvent>

#include "platform_utils.h"

constexpr char LOG_TAG[] = "QRCodeDialog";
constexpr int QR_MODULE_SIZE = 8; // 每个模块的像素大小
constexpr int QR_BORDER = 4; // 边框模块数

QRCodeDialog::QRCodeDialog(const std::shared_ptr<AudioServer> &audio_server, QWidget *parent)
    : QDialog(parent), audio_server_(audio_server) {
    setWindowTitle("配对二维码");
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

    layout_ = new QVBoxLayout(this);

    // 二维码显示标签
    qr_label_ = new QLabel(this);
    qr_label_->setAlignment(Qt::AlignCenter);
    qr_label_->setCursor(Qt::PointingHandCursor); // 设置鼠标悬停时显示手型光标
    qr_label_->installEventFilter(this); // 安装事件过滤器以监听点击事件
    layout_->addWidget(qr_label_);

    // 内容显示标签
    content_label_ = new QLabel(this);
    content_label_->setAlignment(Qt::AlignCenter);
    content_label_->setWordWrap(true);
    content_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout_->addWidget(content_label_);

    // 提示标签
    hint_label_ = new QLabel(MSG_HINT, this);
    hint_label_->setAlignment(Qt::AlignCenter);
    hint_label_->setStyleSheet("color: gray; font-size: 12px;");
    layout_->addWidget(hint_label_);

    setLayout(layout_);

    // 设置固定大小
    setFixedSize(QDialog::sizeHint());

    timer_ = new QTimer(this);
    timer_->setSingleShot(true);
    timer_->setInterval(std::chrono::seconds(30));
    connect(timer_, &QTimer::timeout, std::bind(&QRCodeDialog::expire_pair_code, this));
}

void QRCodeDialog::showEvent(QShowEvent *show_event) {
    QDialog::showEvent(show_event);
    refresh();
}

void QRCodeDialog::refresh() {
    timer_->stop();
    audio_server_->generate_pair_code();

    const std::string ipAddress = PlatformUtils::get_preferred_ip_address();
    const int port = audio_server_->get_port();
    const QString qrContent = QString("sa://%1:%2?%3")
            .arg(QString::fromStdString(ipAddress))
            .arg(port)
            .arg(QString::fromStdString(audio_server_->get_pair_code()));
    setContent(qrContent);
    setFixedSize(QDialog::sizeHint());
    raise();
    activateWindow();

    timer_->start();
}

void QRCodeDialog::hideEvent(QHideEvent *event) {
    QDialog::hideEvent(event);
    clear_pair_code();
}

void QRCodeDialog::clear_pair_code() const {
    audio_server_->clear_pair_code();
    timer_->stop();
}

void QRCodeDialog::expire_pair_code() const {
    qr_label_->setText(MSG_QR_EXPIRED);
    clear_pair_code();
}

void QRCodeDialog::setContent(const QString &content) {
    content_label_->setText(content);
    QPixmap qrPixmap = generateQRCode(content);
    if (!qrPixmap.isNull()) {
        qr_label_->setPixmap(qrPixmap);
    } else {
        qr_label_->setText(MSG_QR_FAIL);
    }
}

QPixmap QRCodeDialog::generateQRCode(const QString &content) {
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

        return QPixmap::fromImage(image);
    } catch (const qrcodegen::data_too_long &e) {
        Logger::e(LOG_TAG, "二维码数据过长: " + std::string(e.what()));
        return QPixmap();
    } catch (const std::exception &e) {
        Logger::e(LOG_TAG, "生成二维码失败: " + std::string(e.what()));
        return QPixmap();
    }
}

bool QRCodeDialog::eventFilter(QObject *obj, QEvent *event) {
    // 监听 qr_label_ 的鼠标点击事件
    if (obj == qr_label_ && event->type() == QEvent::MouseButtonPress) {
        auto *mouseEvent = static_cast<QMouseEvent *>(event);
        if (mouseEvent->button() == Qt::LeftButton) {
            Logger::i(LOG_TAG, "二维码被点击，正在刷新...");
            refresh();
            return true; // 事件已处理
        }
    }
    // 传递给父类处理其他事件
    return QDialog::eventFilter(obj, event);
}
