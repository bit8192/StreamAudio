//
// Created by bincker on 2025/6/28.
//


#ifndef LOGGER_H
#define LOGGER_H
#include <string>
#include <format>

namespace  Logger {

    typedef enum log_level {
        trace,
        debug,
        info,
        warn,
        error,
    } log_level;

    void log(log_level level, const std::string& tag, const std::string& message);

    // 原有的简单版本（保持向后兼容）
    void t(const std::string& tag, const std::string& message);
    void d(const std::string& tag, const std::string& message);
    void i(const std::string& tag, const std::string& message);
    void w(const std::string& tag, const std::string& message);
    void e(const std::string& tag, const std::string& message, const std::exception& e);
    void e(const std::string& tag, const std::string& message);

    // 新的模板版本（支持格式化字符串和多参数）
    template<typename... Args>
    void t(const std::string& tag, std::format_string<Args...> fmt, Args&&... args) {
        log(trace, tag, std::format(fmt, std::forward<Args>(args)...));
    }

    template<typename... Args>
    void d(const std::string& tag, std::format_string<Args...> fmt, Args&&... args) {
        log(debug, tag, std::format(fmt, std::forward<Args>(args)...));
    }

    template<typename... Args>
    void i(const std::string& tag, std::format_string<Args...> fmt, Args&&... args) {
        log(info, tag, std::format(fmt, std::forward<Args>(args)...));
    }

    template<typename... Args>
    void w(const std::string& tag, std::format_string<Args...> fmt, Args&&... args) {
        log(warn, tag, std::format(fmt, std::forward<Args>(args)...));
    }

    template<typename... Args>
    void e(const std::string& tag, std::format_string<Args...> fmt, Args&&... args) {
        log(error, tag, std::format(fmt, std::forward<Args>(args)...));
    }
};



#endif //LOGGER_H
