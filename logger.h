//
// Created by bincker on 2025/6/28.
//


#ifndef LOGGER_H
#define LOGGER_H
#include <string>

namespace  Logger {

    typedef enum log_level {
        trace,
        debug,
        info,
        warn,
        error,
    } log_level;

    void log(log_level level, const std::string& tag, const std::string& message);
    void t(const std::string& tag, const std::string& message);
    void d(const std::string& tag, const std::string& message);
    void i(const std::string& tag, const std::string& message);
    void w(const std::string& tag, const std::string& message);
    void e(const std::string& tag, const std::string& message, const std::exception& e);
    void e(const std::string& tag, const std::string& message);
};



#endif //LOGGER_H
