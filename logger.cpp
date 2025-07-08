//
// Created by bincker on 2025/6/28.
//

#include "logger.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>

void Logger::log(const log_level level, const std::string &tag, const std::string &message) {
    const auto now = std::chrono::system_clock::now();
    const auto now_time = std::chrono::system_clock::to_time_t(now);
    const std::tm now_tm = *std::localtime(&now_time);
    const char* level_str = nullptr;
    switch (level) {
        case error: level_str = "ERROR";
            break;
        case warn: level_str = "WARN";
            break;
        case info: level_str = "INFO";
            break;
        case debug: level_str = "DEBUG";
            break;
        case trace: level_str = "TRACE";
            break;
    }
    std::cout << std::put_time(&now_tm, "%Y-%m-%d %H:%M:%S") << " [" << tag << "] [" << level_str << "] " << message << std::endl;
}

void Logger::t(const std::string &tag, const std::string &message) {
    log(trace, tag, message);
}

void Logger::d(const std::string &tag, const std::string &message) {
    log(debug, tag, message);
}

void Logger::i(const std::string &tag, const std::string &message) {
    log(info, tag, message);
}

void Logger::w(const std::string &tag, const std::string &message) {
    log(warn, tag, message);
}

void Logger::e(const std::string &tag, const std::string &message, const std::exception &e) {
    log(error, tag, message + "\t what=" + e.what());
}

void Logger::e(const std::string &tag, const std::string &message) {
    log(error, tag, message);
}
