
/*
 * Copyright © 2024 <dingjing@live.cn>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

//
// Created by dingjing on 24-3-7.
//

#include "log.h"

#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LOG_IOVEC_MAX               16
#define LOG_FILENAME_LEN            (1024)
#define LOG_DIRNAME_LEN             (1024)
#define LOG_PATH_MAX                (2048)
#define LOG_BUF_SIZE                (20480)
#define PATH_SPLIT                  '/'


#define FG_BLACK                    30
#define FG_RED                      31
#define FG_GREEN                    32
#define FG_YELLOW                   33
#define FG_BLUE                     34
#define FG_MAGENTA                  35
#define FG_CYAN                     36
#define FG_WHITE                    37
#define BG_BLACK                    40
#define BG_RED                      41
#define BG_GREEN                    42
#define BG_YELLOW                   43
#define BG_BLUE                     44
#define BG_MAGENTA                  45
#define BG_CYAN                     46
#define BG_WHITE                    47
#define B_RED(str)                  "\033[1;31m" str "\033[0m"
#define B_GREEN(str)                "\033[1;32m" str "\033[0m"
#define B_YELLOW(str)               "\033[1;33m" str "\033[0m"
#define B_BLUE(str)                 "\033[1;34m" str "\033[0m"
#define B_MAGENTA(str)              "\033[1;35m" str "\033[0m"
#define B_CYAN(str)                 "\033[1;36m" str "\033[0m"
#define B_WHITE(str)                "\033[1;37m" str "\033[0m"
#define RED(str)                    "\033[31m" str "\033[0m"
#define GREEN(str)                  "\033[32m" str "\033[0m"
#define YELLOW(str)                 "\033[33m" str "\033[0m"
#define BLUE(str)                   "\033[34m" str "\033[0m"
#define MAGENTA(str)                "\033[35m" str "\033[0m"
#define CYAN(str)                   "\033[36m" str "\033[0m"
#define WHITE(str)                  "\033[37m" str "\033[0m"


static bool open_file();
static void log_init_once(void);
static cint check_dir (const cchar* path);
static const cchar* get_dir(const cchar* path);
static cuint64 get_file_size(const char *path);
static cint log_open_rewrite(const char *path);
static cint mkdir_r(const char* path, mode_t mode);
static void log_get_time(cchar* str, cint len, cint flag);
static const cchar* file_name(const char* path, cint64 len);
static cint64 log_write(CLogType logType, struct iovec *vec, cint n);
static void log_print(CLogType logType, CLogLevel level, const cchar* tag, const cchar* file, cint line, const cchar* func, const cchar* msg);


static const char* gsLogLevelStr[] = {
    "ERROR",
    "CRIT",
    "WARN",
    "INFO",
    "DEBUG",
    "VERBOSE",
    NULL
};


//static CLogType gsLogType = C_LOG_TYPE_CONSOLE;                       // 日志默认输出到控制台
static unsigned long long gsLogSize = 0;                                // 日志文件大小
static CLogLevel gsLogLevel = C_LOG_LEVEL_WARNING;                      // 输出日至级别
static char gsLogDir[LOG_DIRNAME_LEN] = "./";                           // 日志输出文件夹
static char gsLogPrefix[LOG_FILENAME_LEN] = "log";                      // 日志名称
static char gsLogSuffix[LOG_FILENAME_LEN] = "log";                      // 日志扩展名
static char gsPathName[LOG_PATH_MAX] = {0};                             // 完整日志路径
static int gsLogFd = 0;                                                 // 当前打开的日志文件描述符
static bool gsHasTime = false;                                          // 文件名中是否带时间

static pthread_mutex_t gsLogMutex;                                      // 日志锁
static pthread_once_t gsThreadOnce = PTHREAD_ONCE_INIT;                 // 确保初始化一次
static bool gsIsLogInit = false;                                        // 是否完成初始化


bool c_log_init(CLogLevel level, cuint64 logSize, const cchar *dir, const cchar *prefix, const cchar *suffix, bool hasTime)
{
    if (0 != pthread_once(&gsThreadOnce, log_init_once)) {
        fprintf(stderr, "pthread_once error, log_init failed\n");
        return false;
    }

    if(0 != pthread_mutex_lock(&gsLogMutex)) {
        fprintf(stderr, "pthread_mutex_lock error, log_init failed\n");
        return false;
    }

    gsLogLevel = level;
    gsHasTime = hasTime;
    if (logSize > 0) {
        gsLogSize = logSize;
    }
    else {
        gsLogSize = 2 << 20;
    }
    if (NULL != dir) {
        unsigned long dl = strlen(dir);
        if(dl > 2) {
            if(0 == strncmp(dir, "./", 2) || 0 == strncmp(dir, "/", 1)) {
                snprintf(gsLogDir, sizeof(gsLogDir) - 2, "%s/", dir);
            } else {
                snprintf(gsLogDir, sizeof(gsLogDir) - 4, "./%s/", dir);
            }
        } else {
            if (0 == strncmp(dir, "/", 1)) {
                strncpy(gsLogDir, dir, sizeof(gsLogDir) - 1);
            } else {
                fprintf(stderr, "dir name is invalide!\n");
            }
        }
    }
    if (NULL != prefix) {
        strncpy(gsLogPrefix, prefix, (cuint64) C_N_ELEMENTS(gsLogPrefix) - 1);
    }
    if (NULL != suffix) {
        strncpy(gsLogSuffix, suffix, (cuint64) C_N_ELEMENTS(gsLogSuffix) - 1);
    }

    if (!open_file()) {
        goto RET_ERR;
    }

    if(0 != pthread_mutex_unlock(&gsLogMutex)) {
        fprintf(stderr, "pthread_mutex_unlock error, log_init failed\n");
        goto RET_ERR;
    }

    return true;

RET_ERR:
    pthread_mutex_unlock(&gsLogMutex);
    return false;
}

void c_log_destroy(void)
{
    if (C_UNLIKELY(!c_log_is_inited())) {
        return;
    }
    gsIsLogInit = false;
    pthread_mutex_lock(&gsLogMutex);
    close(gsLogFd);
    gsThreadOnce = PTHREAD_ONCE_INIT;
    pthread_mutex_unlock(&gsLogMutex);
    pthread_mutex_destroy(&gsLogMutex);
}

void c_log_print(CLogLevel level, const cchar *tag, const cchar *file, cint line, const cchar *func, const cchar *fmt,...)
{
    va_list ap;
    char buf[LOG_BUF_SIZE] = {0};
    int n;
    if (level > gsLogLevel) {
        return;
    }

    if (C_UNLIKELY(!c_log_is_inited())) {
        fprintf(stderr, "log has not been initialized!\n");
        return;
    }
    va_start(ap, fmt);
    n = vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
    if(n < 0) {
        return;
    }

    log_print(C_LOG_TYPE_FILE, level, tag, file, line, func, buf);
}

void c_log_print_console (CLogLevel level, const cchar* tag, const cchar* file, int line, const cchar* func, const cchar* fmt, ...)
{
    if (level > gsLogLevel) {
        return;
    }

    va_list ap;
    char buf[LOG_BUF_SIZE] = {0};
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
    if(n < 0) {
        return;
    }

    log_print(C_LOG_TYPE_CONSOLE, level, tag, file, line, func, buf);
}

bool c_log_is_inited()
{
    return gsIsLogInit;
}

void c_log_raw(CLogLevel level, const cchar *fmt, ...)
{
    if (level > gsLogLevel) {
        return;
    }

    va_list ap;
    char buf[LOG_BUF_SIZE] = {0};
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, LOG_BUF_SIZE - 1, fmt, ap);
    va_end(ap);
    if(n < 0) {
        return;
    }

    struct iovec vec[2];
    vec[0].iov_base = buf;
    vec[0].iov_len = strlen(buf);

    vec[1].iov_base = "\n";
    vec[1].iov_len = 1;

    log_write(C_LOG_TYPE_FILE, vec, 2);
}

static void log_print(CLogType logType, CLogLevel level, const cchar* tag, const cchar* file, cint line, const cchar* func, const cchar* msg)
{
    struct iovec vec[LOG_IOVEC_MAX];
    char s_time[LOG_FILENAME_LEN] = {0};
    char s_level[LOG_FILENAME_LEN] = {0};
    char s_tag[LOG_FILENAME_LEN] = {0};
    char s_pid[LOG_FILENAME_LEN] = {0};
    char s_file[LOG_DIRNAME_LEN] = {0};
    char s_msg[LOG_BUF_SIZE] = {0};

    pthread_mutex_lock(&gsLogMutex);
    log_get_time(s_time, sizeof(s_time), 0);
    if(C_LOG_TYPE_CONSOLE == logType) {
        switch(level) {
            case C_LOG_LEVEL_ERROR: {
                snprintf (s_level, sizeof (s_level), B_RED("[%s] "), gsLogLevelStr[level]);
                snprintf (s_msg, sizeof (s_msg), RED(" %s"), msg);
                break;
            }
            case C_LOG_LEVEL_CRIT: {
                snprintf (s_level, sizeof (s_level), B_YELLOW("[%s] "), gsLogLevelStr[level]);
                snprintf (s_msg, sizeof (s_msg), YELLOW(" %s"), msg);
                break;
            }
            case C_LOG_LEVEL_WARNING: {
                snprintf (s_level, sizeof (s_level), B_BLUE("[%s] "), gsLogLevelStr[level]);
                snprintf (s_msg, sizeof (s_msg), BLUE(" %s"), msg);
                break;
            }
            case C_LOG_LEVEL_INFO: {
                snprintf (s_level, sizeof (s_level), B_GREEN("[%s] "), gsLogLevelStr[level]);
                snprintf (s_msg, sizeof (s_msg), GREEN(" %s"), msg);
                break;
            }
            case C_LOG_LEVEL_DEBUG: {
                snprintf (s_level, sizeof (s_level), B_CYAN("[%s] "), gsLogLevelStr[level]);
                snprintf (s_msg, sizeof (s_msg), CYAN(" %s"), msg);
                break;
            }
            case C_LOG_LEVEL_VERB:
            default: {
                snprintf (s_level, sizeof (s_level), B_WHITE("[%s] "), gsLogLevelStr[level]);
                snprintf (s_msg, sizeof (s_msg), WHITE(" %s"), msg);
                break;
            }
        }
    }
    else {
        snprintf(s_level, sizeof(s_level) - 1, "[%s] ", gsLogLevelStr[level]);
        snprintf(s_msg, sizeof(s_msg) - 1, " %s", (NULL == msg) ? "<null>" : msg);
    }

    if (strlen (tag) > 0) {
        snprintf(s_tag, sizeof(s_tag), "[%s] ", tag);
    }

    snprintf(s_pid, sizeof(s_pid), "pid:%d", getpid());

    if (strlen (file) > 0) {
        snprintf(s_file, sizeof(s_file) - 1, " %s:%d: %s", file_name(file, (cint64) strlen(file)), line, func);
    }

    int i = -1;
    vec[++i].iov_base = (void*)s_time;
    vec[i].iov_len = strlen(s_time);
    vec[++i].iov_base = " ";
    vec[i].iov_len = 1;
    vec[++i].iov_base = (void*)s_tag;
    vec[i].iov_len = strlen(s_tag);
    vec[++i].iov_base = (void*)s_level;
    vec[i].iov_len = strlen(s_level);
    vec[++i].iov_base = "[";
    vec[i].iov_len = 1;
    vec[++i].iov_base = (void*)s_pid;
    vec[i].iov_len = strlen(s_pid);
    vec[++i].iov_base = (void*)s_file;
    vec[i].iov_len = strlen(s_file);
    vec[++i].iov_base = "]";
    vec[i].iov_len = 1;
    vec[++i].iov_base = (void*)s_msg;
    vec[i].iov_len = strlen(s_msg);
    vec[++i].iov_base = "\n";
    vec[i].iov_len = 1;

    log_write(logType, vec, ++i);

    pthread_mutex_unlock(&gsLogMutex);
}

static const char* file_name(const char* path, cint64 len)
{
    if (NULL == path) {
        return path;
    }
    char* pend = NULL;
    pend = (char*)path + len;
    int i = 0;
    for(i = 1; i < len; ++i) {
        if((pend - i == path)
            || (*(pend - i) == '/')
            || (*(pend - i) == '\\')) {
            break;
        }
    }
    if(i >= 2) i--;

    return pend - i;
}

static cuint64 get_file_size(const char *path)
{
    struct stat buf;
    if (stat(path, &buf) < 0) {
        return 0;
    }
    return (cuint64) buf.st_size;
}

static int log_open_rewrite(const char *path)
{
    check_dir(path);
    gsLogFd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (gsLogFd == -1) {
        fprintf(stderr, "open %s failed: %s\n", path, strerror(errno));
        fprintf(stderr, "use STDERR_FILEIO as output\n");
        gsLogFd = STDERR_FILENO;
    }
    return 0;
}

static cint64 log_write(CLogType logType, struct iovec *vec, cint n)
{
    switch (logType) {
        default: {}
        case C_LOG_TYPE_CONSOLE: {
            return writev(STDOUT_FILENO, vec, n);
        }
        case C_LOG_TYPE_FILE: {
            unsigned long long tmpSize = get_file_size(gsPathName);
            if (tmpSize >= gsLogSize) {
                if (-1 == close(gsLogFd)) {
                    fprintf(stderr, "close file errno:%d", errno);
                }
                log_open_rewrite(gsPathName);
            }
            return writev(gsLogFd, vec, n);
        }
    }
}


static const cchar* get_dir(const cchar* path)
{
    char* p = (char*) path + strlen(path);
    for(; p != path; p--) {
        if('/' == *p) {
            *(p + 1) = '\0';
            break;
        }
    }
    return path;
}

static int mkdir_r(const char* path, mode_t mode)
{
    int ret = 0;
    char* temp = NULL;
    char* pos = NULL;
    if(NULL == path) {
        return -1;
    }
    temp = strdup(path);
    pos = temp;
    if(0 == strncmp(temp, "/", 1)) {
        pos += 1;
    } else if(0 == strncmp(temp, "./", 2)) {
        pos += 2;
    }
    for(; *pos != '\0'; ++ pos) {
        if(*pos == '/') {
            *pos = '\0';
            if (-1 == (ret = mkdir(temp, mode))) {
                if(errno == EEXIST) {
                    ret = 0;
                } else {
                    fprintf(stderr, "fail to mkdir %s: %d:%s\n",
                            temp, errno, strerror(errno));
                    break;
                }
            }
            *pos = '/';
        }
    }
    if(*(pos - 1) != '/') {
        if(-1 == (ret = mkdir(temp, mode))) {
            if(errno == EEXIST) {
                ret = 0;
            } else {
                fprintf(stderr, "failed to mkdir %s: %d:%s\n",
                        temp, errno, strerror(errno));
            }
        }
    }
    free(temp);
    return ret;
}

static cint check_dir (const cchar* path)
{
    char* pathTmp = NULL;
    const char* dir = NULL;
    pathTmp = strdup(path);
    if(NULL != strstr(path, "/")) {
        dir = get_dir(pathTmp);
        if (-1 == access(dir, F_OK | W_OK | R_OK)) {
            if(-1 == mkdir_r(dir, 0776)) {
                fprintf(stderr, "mkdir %s failed\n", pathTmp);
                goto RET_ERR;
            }
        }
    }

    free(pathTmp);
    return 0;

RET_ERR:
    free(pathTmp);

    return -1;
}

static void log_get_time(cchar* str, cint len, cint flag)
{
    char dateFmt[32] = {0};
    char dateMs[8] = {0};
    struct timeval tv;
    struct tm nowTm;
    cuint8 nowMs;
    time_t nowSec;
    gettimeofday(&tv, NULL);
    nowSec = tv.tv_sec;
    nowMs = tv.tv_usec/1000;
    localtime_r(&nowSec, &nowTm);

    if (0 == flag) {
        strftime(dateFmt, C_N_ELEMENTS(dateFmt) - 1, "%Y-%m-%d %H:%M:%S", &nowTm);
        snprintf(dateMs, C_N_ELEMENTS(dateMs) - 1, "%03u", nowMs);
        snprintf(str, (cuint64) (len - 1), "[%s.%s]", dateFmt, dateMs);
    }
    else {
        strftime(dateFmt, C_N_ELEMENTS(dateFmt) - 1, "%Y_%m_%d", &nowTm);
        snprintf(str, (cuint64) (len - 1), "%s", dateFmt);
    }
}

static bool open_file()
{
    if(0 != check_dir(gsLogDir)) {
        fprintf(stderr, "check_dir error, log_init failed\n");
        return false;
    }

    if (gsHasTime) {
        char time_str[LOG_FILENAME_LEN] = {0};
        log_get_time(time_str, sizeof(time_str), 1);
        if(0 >= snprintf(gsPathName, sizeof(gsPathName), "%s/%s_%s.%s",
                            gsLogDir, gsLogPrefix, time_str, gsLogSuffix)) {
            return false;
        }
    }
    else {
        if(0 >= snprintf(gsPathName, sizeof(gsPathName), "%s/%s.%s",
                            gsLogDir, gsLogPrefix, gsLogSuffix)) {
            return false;
        }
    }

    const int mask = umask(0);
    gsLogFd = open(gsPathName, O_CREAT | O_RDWR | O_APPEND, 0666);
    umask(mask);
    if(-1 == gsLogFd) {
        fprintf(stderr, "open %s error: %s, log_init failed\n",
                gsPathName, strerror(errno));
        gsLogFd = STDERR_FILENO;
        return false;
    }

    return true;
}

static void log_init_once(void)
{
    if(C_UNLIKELY(c_log_is_inited())) {
        return;
    }

    gsIsLogInit = true;
    pthread_mutex_init(&gsLogMutex, NULL);
}
