#include "log.h"
#include <cstdlib>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>

void initLogFile() {
    logFd = open("profiler.log", O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if (logFd == -1) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }
}

void logMessage(LogLevel level, const char *file, int line, const char *format, ...) {
#ifdef LOG_LEVEL
    if (level < LOG_LEVEL) {
        return;
    }
#endif
    const char *levelStr[] = {"DEBUG", "INFO", "WARNING", "ERROR"};
    const char *colorStr[] = {COLOR_DEBUG, COLOR_INFO, COLOR_WARNING, COLOR_ERROR};

    if (logFd == -1) {
        initLogFile();
    }

    char buffer[500];
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *timeinfo;
    timeinfo = localtime(&tv.tv_sec);

    char time_buffer[30];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    // 将时间、日志级别、文件名、行号等信息写入缓冲区
    int offset = snprintf(buffer, sizeof(buffer), "%s[%s", colorStr[level], time_buffer);

    // 添加毫秒
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, ".%03ld", tv.tv_usec / 1000);

    // 继续追加日志的其他部分
    offset += snprintf(buffer + offset, sizeof(buffer) - offset, "] [%s:%d] %s: %s", 
                       file, line, levelStr[level], COLOR_RESET);;

    va_list args;
    va_start(args, format);
    vsnprintf(buffer + offset, 500 - offset, format, args);
    va_end(args);

    strcat(buffer, "\n");
    write(logFd, buffer, strlen(buffer));

    if (level == LOG_ERROR) {
        // exit(EXIT_FAILURE);
    }
}
