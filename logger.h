//
// Created by bincker on 2025/6/28.
//

#ifndef LOGGER_H
#define LOGGER_H
#include <string>

typedef enum log_level {
    trace,
    debug,
    info,
    warn,
    error,
} log_level;

class Logger {
public:
    static void log(log_level level, const std::string& tag, const std::string& message);
    static void t(const std::string& tag, const std::string& message);
    static void d(const std::string& tag, const std::string& message);
    static void i(const std::string& tag, const std::string& message);
    static void w(const std::string& tag, const std::string& message);
    static void e(const std::string& tag, const std::string& message, const std::exception& e);
    static void e(const std::string& tag, const std::string& message);
};



#endif //LOGGER_H
