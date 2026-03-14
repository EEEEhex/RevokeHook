#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <mutex>
#include <map>
#include <memory>
#include <direct.h>     //用于创建文件夹

namespace MyLogger {
    //日志等级
    enum class LogLevel {
        LDEBUG,
        LINFO,
        LWARNING,
        LERROR,
        LFATAL
    };

    bool create_directory(const std::string& path) {
        int ret = _mkdir(path.c_str());
        return (ret == 0 || errno == EEXIST);
    }

    class Logger {
    public:
        // 单例模式获取logger实例
        static Logger& getInstance() {
            static Logger instance;
            return instance;
        }

        // 设置日志输出目标 (true: 输出到文件, false: 输出到控制台)
        void setOutputToFile(bool toFile) {
            std::lock_guard<std::mutex> lock(mutex_);
            outputToFile_ = toFile;
        }

        // 设置日志等级
        void setLogLevel(LogLevel level) {
            std::lock_guard<std::mutex> lock(mutex_);
            logLevel_ = level;
        }

        // 设置日志文件路径
        void setLogFilePath(const std::string& path) {
            std::lock_guard<std::mutex> lock(mutex_);
            logPath_ = path;
            if (logPath_.back() != '/' && logPath_.back() != '\\') {
                logPath_ += "/";
            }
        }

        // 日志输出接口
        void log(LogLevel level, const std::string& message) {
            std::lock_guard<std::mutex> lock(mutex_);

            if (level < logLevel_) {
                return;
            }

            // 获取当前时间并格式化
            auto now = std::chrono::system_clock::now();
            auto timestamp = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) % 1000;

            std::tm localTime;
#ifdef _WIN32
            localtime_s(&localTime, &timestamp);
#else
            localtime_r(&timestamp, &localTime);
#endif

            std::ostringstream timeStream;
            timeStream << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S")
                << '.' << std::setfill('0') << std::setw(3) << ms.count();
            std::string timeStr = timeStream.str();

            // 获取日期字符串（用于文件名）
            std::ostringstream dateStream;
            dateStream << std::put_time(&localTime, "%Y-%m-%d");
            std::string dateStr = dateStream.str();

            // 获取日志级别字符串
            std::string levelStr = getLevelString(level);

            // 构造完整日志消息
            std::ostringstream logStream;
            logStream << "[" << timeStr << "] " << "[" << levelStr << "] " << message;
            std::string logMessage = logStream.str();

            if (outputToFile_) {
                // 输出到按日期命名的文件
                writeToFile(dateStr, logMessage);
            }
            else {
                // 输出到控制台
                if (level >= LogLevel::LWARNING) {
                    std::cerr << logMessage << std::endl;
                }
                else {
                    std::cout << logMessage << std::endl;
                }
            }
        }

        // 便捷的日志方法
        void debug(const std::string& message) {
            log(LogLevel::LDEBUG, message);
        }

        void info(const std::string& message) {
            log(LogLevel::LINFO, message);
        }

        void warning(const std::string& message) {
            log(LogLevel::LWARNING, message);
        }

        void error(const std::string& message) {
            log(LogLevel::LERROR, message);
        }

        void fatal(const std::string& message) {
            log(LogLevel::LFATAL, message);
        }

    private:
        Logger() : outputToFile_(false), logLevel_(LogLevel::LDEBUG), logPath_("./logs/") {
            // 创建日志目录
        /*
#ifdef _WIN32
            system(("mkdir " + logPath_ + " 2>nul").c_str());
#else
            system(("mkdir -p " + logPath_).c_str());
#endif
        */
            if (!create_directory(logPath_)) std::cerr << "Failed to create log dir!" << std::endl;
        }

        ~Logger() {
            // 关闭所有打开的文件
            for (auto& file : logFiles_) {
                if (file.second && file.second->is_open()) {
                    file.second->close();
                }
            }
        }

        // 禁止拷贝和赋值
        Logger(const Logger&) = delete;
        Logger& operator=(const Logger&) = delete;

        // 将日志写入文件
        void writeToFile(const std::string& dateStr, const std::string& message) {
            std::string fileName = logPath_ + "log_" + dateStr + ".txt";

            // 查看是否已经打开该日期的文件
            if (logFiles_.find(dateStr) == logFiles_.end() || !logFiles_[dateStr]->is_open()) {
                logFiles_[dateStr] = std::make_unique<std::ofstream>(fileName, std::ios::app);
                if (!logFiles_[dateStr]->is_open()) {
                    std::cerr << "Failed to open log file: " << fileName << std::endl;
                    return;
                }
            }

            // 写入日志
            (*logFiles_[dateStr]) << message << std::endl;
        }

        // 将日志级别转换为字符串
        std::string getLevelString(LogLevel level) {
            switch (level) {
            case LogLevel::LDEBUG:   return "DEBUG";
            case LogLevel::LINFO:    return "INFO";
            case LogLevel::LWARNING: return "WARNING";
            case LogLevel::LERROR:   return "ERROR";
            case LogLevel::LFATAL:   return "FATAL";
            default:                return "UNKNOWN";
            }
        }

        bool outputToFile_;                  // 是否输出到文件
        LogLevel logLevel_;                  // 日志等级
        std::string logPath_;                // 日志文件路径
        std::mutex mutex_;                   // 互斥锁，确保线程安全
        std::map<std::string, std::unique_ptr<std::ofstream>> logFiles_;  // 日期到文件的映射
    };

    // 宏定义，方便使用
#define LOG_DEBUG(msg)    Logger::getInstance().debug(msg)
#define LOG_INFO(msg)     Logger::getInstance().info(msg)
#define LOG_WARNING(msg)  Logger::getInstance().warning(msg)
#define LOG_ERROR(msg)    Logger::getInstance().error(msg)
#define LOG_FATAL(msg)    Logger::getInstance().fatal(msg)
}