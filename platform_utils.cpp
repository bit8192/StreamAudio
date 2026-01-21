//
// Created by Claude on 2026/1/9.
//

#include "platform_utils.h"
#include <QNetworkInterface>
#include <QHostAddress>
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QTextStream>

#ifdef _WIN32
#include <QSettings>
#endif

namespace PlatformUtils {

std::vector<std::string> get_local_ip_addresses() {
    std::vector<std::string> addresses;

    const QList<QHostAddress> allAddresses = QNetworkInterface::allAddresses();
    for (const QHostAddress& address : allAddresses) {
        // 只获取 IPv4 地址，排除回环地址
        if (address.protocol() == QAbstractSocket::IPv4Protocol &&
            !address.isLoopback()) {
            addresses.push_back(address.toString().toStdString());
        }
    }

    return addresses;
}

std::string get_preferred_ip_address() {
    std::vector<std::string> addresses = get_local_ip_addresses();

    if (addresses.empty()) {
        return "127.0.0.1";  // 如果没有找到地址，返回回环地址
    }

    // 优先返回局域网地址 (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    for (const auto& addr : addresses) {
        if (addr.starts_with("192.168.") ||
            addr.starts_with("10.") ||
            addr.starts_with("172.")) {
            return addr;
        }
    }

    // 如果没有找到局域网地址，返回第一个地址
    return addresses[0];
}

static QString get_autostart_file_path() {
#ifdef _WIN32
    return {};
#else
    const QString config_dir = QStandardPaths::writableLocation(QStandardPaths::ConfigLocation);
    if (config_dir.isEmpty()) {
        return {};
    }
    return QDir(config_dir).filePath("autostart/StreamAudio.desktop");
#endif
}

bool is_auto_start_enabled() {
#ifdef _WIN32
    const QString run_key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    QSettings settings(run_key, QSettings::NativeFormat);
    return settings.contains("StreamAudio");
#else
    const QString desktop_file = get_autostart_file_path();
    return !desktop_file.isEmpty() && QFileInfo::exists(desktop_file);
#endif
}

static QString escape_desktop_exec(QString path) {
    path.replace("\\", "\\\\");
    path.replace(" ", "\\ ");
    return path;
}

bool set_auto_start_enabled(const bool enabled, std::string* error) {
    if (error) {
        error->clear();
    }

#ifdef _WIN32
    const QString run_key = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    QSettings settings(run_key, QSettings::NativeFormat);
    const QString value_name = "StreamAudio";
    if (enabled) {
        QString exe = QCoreApplication::applicationFilePath();
        exe.replace("/", "\\");
        settings.setValue(value_name, QString("\"%1\"").arg(exe));
    } else {
        settings.remove(value_name);
    }
    settings.sync();
    if (settings.status() != QSettings::NoError) {
        if (error) {
            *error = "write registry failed";
        }
        return false;
    }
    return true;
#else
    const QString desktop_file = get_autostart_file_path();
    if (desktop_file.isEmpty()) {
        if (error) {
            *error = "autostart path not available";
        }
        return false;
    }

    if (!enabled) {
        if (QFileInfo::exists(desktop_file) && !QFile::remove(desktop_file)) {
            if (error) {
                *error = "remove autostart file failed";
            }
            return false;
        }
        return true;
    }

    QDir dir(QFileInfo(desktop_file).absolutePath());
    if (!dir.exists() && !dir.mkpath(".")) {
        if (error) {
            *error = "create autostart dir failed";
        }
        return false;
    }

    QFile file(desktop_file);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        if (error) {
            *error = "open autostart file failed";
        }
        return false;
    }

    const QString exec = escape_desktop_exec(QCoreApplication::applicationFilePath());

    QTextStream out(&file);
    out.setEncoding(QStringConverter::Utf8);
    out << "[Desktop Entry]\n";
    out << "Type=Application\n";
    out << "Name=StreamAudio\n";
    out << "Exec=" << exec << "\n";
    out << "Terminal=false\n";
    out << "X-GNOME-Autostart-enabled=true\n";
    file.close();

    return true;
#endif
}

}
