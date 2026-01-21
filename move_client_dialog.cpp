//
// Created by OpenCode on 2026/1/21.
//

#include "move_client_dialog.h"

#include "logger.h"
#include "platform_utils.h"
#include "tools/qrcodegen.hpp"

#include <QCloseEvent>
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QImage>
#include <QMessageBox>
#include <QPainter>
#include <QShowEvent>
#include <QTcpSocket>
#include <QVBoxLayout>
#include <QtGlobal>

constexpr char LOG_TAG[] = "MoveClientDialog";
constexpr int QR_MODULE_SIZE = 8;
constexpr int QR_BORDER = 4;

static QByteArray http_response_header(
    const QByteArray& status,
    const QByteArray& content_type,
    qint64 content_length,
    const QByteArray& extra_headers = {}
) {
    QByteArray header;
    header += "HTTP/1.1 ";
    header += status;
    header += "\r\n";
    header += "Connection: close\r\n";
    header += "Content-Type: ";
    header += content_type;
    header += "\r\n";
    if (content_length >= 0) {
        header += "Content-Length: ";
        header += QByteArray::number(content_length);
        header += "\r\n";
    }
    if (!extra_headers.isEmpty()) {
        header += extra_headers;
        if (!extra_headers.endsWith("\r\n")) {
            header += "\r\n";
        }
    }
    header += "\r\n";
    return header;
}

MoveClientDialog::MoveClientDialog(QWidget* parent)
    : QDialog(parent) {
    setWindowTitle("移动客户端");
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);

    auto* layout = new QVBoxLayout(this);

    qr_label_ = new QLabel(this);
    qr_label_->setAlignment(Qt::AlignCenter);
    layout->addWidget(qr_label_);

    url_label_ = new QLabel(this);
    url_label_->setAlignment(Qt::AlignCenter);
    url_label_->setWordWrap(true);
    url_label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(url_label_);

    hint_label_ = new QLabel("手机扫描二维码下载 APK，然后在手机上安装（需要允许安装未知来源）", this);
    hint_label_->setAlignment(Qt::AlignCenter);
    hint_label_->setStyleSheet("color: gray; font-size: 12px;");
    layout->addWidget(hint_label_);

    setLayout(layout);
    setFixedSize(QDialog::sizeHint());

    server_ = new QTcpServer(this);
    connect(server_, &QTcpServer::newConnection, this, &MoveClientDialog::on_new_connection);
}

MoveClientDialog::~MoveClientDialog() {
    stop_http_server();
}

void MoveClientDialog::showEvent(QShowEvent* event) {
    QDialog::showEvent(event);
    update_content();
}

void MoveClientDialog::closeEvent(QCloseEvent* event) {
    stop_http_server();
    QDialog::closeEvent(event);
}

void MoveClientDialog::update_content() {
    apk_path_ = find_apk_file();
    if (apk_path_.isEmpty()) {
        stop_http_server();
        qr_label_->setText("未找到 APK");
        url_label_->setText("请先构建 Android APK，或将 APK 放到可执行文件目录下并命名为 StreamAudio.apk\n也可设置环境变量 STREAMAUDIO_APK_PATH 指定 APK 路径");
        setFixedSize(QDialog::sizeHint());
        return;
    }

    if (!start_http_server()) {
        qr_label_->setText("HTTP 服务启动失败");
        url_label_->setText("无法启动本地 HTTP 服务，请检查端口占用或权限");
        setFixedSize(QDialog::sizeHint());
        return;
    }

    const QString ip = QString::fromStdString(PlatformUtils::get_preferred_ip_address());
    const quint16 port = server_->serverPort();
    url_ = QString("http://%1:%2/streamaudio.apk").arg(ip).arg(port);

    url_label_->setText(url_);
    const QPixmap qr = generate_qrcode(url_);
    if (!qr.isNull()) {
        qr_label_->setPixmap(qr);
    } else {
        qr_label_->setText("生成二维码失败");
    }

    setFixedSize(QDialog::sizeHint());
    raise();
    activateWindow();
}

bool MoveClientDialog::start_http_server() {
    if (!server_) {
        return false;
    }

    if (server_->isListening()) {
        return true;
    }

    if (!server_->listen(QHostAddress::Any, 0)) {
        Logger::e(LOG_TAG, "Failed to listen: " + server_->errorString().toStdString());
        return false;
    }

    Logger::i(LOG_TAG, "HTTP server started on port {}", server_->serverPort());
    return true;
}

void MoveClientDialog::stop_http_server() {
    if (server_ && server_->isListening()) {
        Logger::i(LOG_TAG, "HTTP server stopped");
        server_->close();
    }
}

QString MoveClientDialog::find_apk_file() {
    const QString env_path = qEnvironmentVariable("STREAMAUDIO_APK_PATH");
    if (!env_path.isEmpty() && QFileInfo::exists(env_path)) {
        return QFileInfo(env_path).absoluteFilePath();
    }

    const QString app_dir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        app_dir + "/StreamAudio.apk",
        app_dir + "/StreamAudioAndroid.apk",
        app_dir + "/client.apk",
        app_dir + "/../StreamAudioAndroid/app/build/outputs/apk/release/app-release.apk",
        app_dir + "/../StreamAudioAndroid/app/build/outputs/apk/debug/app-debug.apk",
        app_dir + "/../../StreamAudioAndroid/app/build/outputs/apk/release/app-release.apk",
        app_dir + "/../../StreamAudioAndroid/app/build/outputs/apk/debug/app-debug.apk",
    };

    for (const auto& path : candidates) {
        if (QFileInfo::exists(path)) {
            return QFileInfo(path).absoluteFilePath();
        }
    }

    return {};
}

QPixmap MoveClientDialog::generate_qrcode(const QString& content) {
    try {
        const auto data = content.toUtf8();
        const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(
            data,
            qrcodegen::QrCode::Ecc::LOW
        );

        const int size = qr.getSize();
        const int imageSize = (size + QR_BORDER * 2) * QR_MODULE_SIZE;
        QImage image(imageSize, imageSize, QImage::Format_RGB16);
        image.fill(Qt::white);

        QPainter painter(&image);
        painter.setPen(Qt::NoPen);
        painter.setBrush(Qt::black);

        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) {
                if (qr.getModule(x, y)) {
                    const int pixelX = (x + QR_BORDER) * QR_MODULE_SIZE;
                    const int pixelY = (y + QR_BORDER) * QR_MODULE_SIZE;
                    painter.fillRect(pixelX, pixelY, QR_MODULE_SIZE, QR_MODULE_SIZE, Qt::black);
                }
            }
        }
        painter.end();

        return QPixmap::fromImage(image);
    } catch (const std::exception& e) {
        Logger::e(LOG_TAG, "Generate QR code failed: " + std::string(e.what()));
        return {};
    }
}

void MoveClientDialog::on_new_connection() {
    while (server_->hasPendingConnections()) {
        QTcpSocket* socket = server_->nextPendingConnection();
        if (!socket) {
            continue;
        }

        socket->setProperty("req_buf", QByteArray());
        connect(socket, &QTcpSocket::readyRead, this, [this, socket] {
            QByteArray buf = socket->property("req_buf").toByteArray();
            buf += socket->readAll();
            if (!buf.contains("\r\n\r\n")) {
                socket->setProperty("req_buf", buf);
                return;
            }

            const int line_end = buf.indexOf("\r\n");
            if (line_end <= 0) {
                socket->disconnectFromHost();
                return;
            }

            const QByteArray request_line = buf.left(line_end);
            const QList<QByteArray> parts = request_line.split(' ');
            if (parts.size() < 2) {
                socket->disconnectFromHost();
                return;
            }

            const QByteArray method = parts[0];
            const QByteArray path = parts[1];
            if (method != "GET") {
                const QByteArray body = "Method Not Allowed";
                socket->write(http_response_header("405 Method Not Allowed", "text/plain; charset=utf-8", body.size()));
                socket->write(body);
                socket->disconnectFromHost();
                return;
            }

            if (path == "/" || path == "/index.html") {
                const QFileInfo fi(apk_path_);
                const QString file_name = fi.fileName().isEmpty() ? QString("StreamAudio.apk") : fi.fileName();
                const QString html = QString(
                    "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
                    "<title>StreamAudio</title></head><body style='font-family: sans-serif; padding: 16px'>"
                    "<h2>StreamAudio Android 客户端</h2>"
                    "<p><a href='/streamaudio.apk' style='font-size: 18px'>点击下载 %1</a></p>"
                    "<p style='color: #666'>下载后打开文件安装，可能需要允许安装未知来源应用。</p>"
                    "</body></html>"
                ).arg(file_name);
                const QByteArray body = html.toUtf8();
                socket->write(http_response_header("200 OK", "text/html; charset=utf-8", body.size()));
                socket->write(body);
                socket->disconnectFromHost();
                return;
            }

            if (path == "/streamaudio.apk") {
                QFile file(apk_path_);
                if (!file.open(QIODevice::ReadOnly)) {
                    const QByteArray body = "APK not found";
                    socket->write(http_response_header("404 Not Found", "text/plain; charset=utf-8", body.size()));
                    socket->write(body);
                    socket->disconnectFromHost();
                    return;
                }

                const QByteArray extra = "Content-Disposition: attachment; filename=\"StreamAudio.apk\"\r\n";
                socket->write(http_response_header(
                    "200 OK",
                    "application/vnd.android.package-archive",
                    file.size(),
                    extra
                ));

                while (!file.atEnd()) {
                    socket->write(file.read(64 * 1024));
                }
                socket->disconnectFromHost();
                return;
            }

            const QByteArray body = "Not Found";
            socket->write(http_response_header("404 Not Found", "text/plain; charset=utf-8", body.size()));
            socket->write(body);
            socket->disconnectFromHost();
        });

        connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
    }
}
