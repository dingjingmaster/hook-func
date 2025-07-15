
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

#ifndef CLIBRARY_LOG_H
#define CLIBRARY_LOG_H

#include "macros/macros.h"

C_BEGIN_EXTERN_C

#ifndef C_LOG_TAG
#define C_LOG_TAG      "clog"
#endif

#ifndef C_LOG_SIZE
#define C_LOG_SIZE     (200 * 2 << 10)         // 200mb
#endif

#ifndef C_LOG_DIR
#define C_LOG_DIR      "/tmp/"
#endif

#ifdef DEBUG
#define C_LOG_LEVEL    C_LOG_LEVEL_VERB
#else
#define C_LOG_LEVEL    C_LOG_LEVEL_INFO
#endif


#define C_LOG_INIT_IF_NOT_INIT \
C_STMT_START { \
    if (C_UNLIKELY(!c_log_is_inited())) { \
        c_log_init (C_LOG_LEVEL, C_LOG_SIZE, C_LOG_DIR, C_LOG_TAG, "log", false); \
    } \
} C_STMT_END


#define C_LOG_ERROR(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print(C_LOG_LEVEL_ERROR, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END

#define C_LOG_CRIT(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print(C_LOG_LEVEL_CRIT, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END

#define C_LOG_WARNING(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print(C_LOG_LEVEL_WARNING, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END

#define C_LOG_INFO(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print(C_LOG_LEVEL_INFO, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END


#define C_LOG_ERROR_CONSOLE(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print_console(C_LOG_LEVEL_ERROR, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END

#define C_LOG_CRIT_CONSOLE(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print_console(C_LOG_LEVEL_CRIT, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END

#define C_LOG_WARNING_CONSOLE(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print_console(C_LOG_LEVEL_WARNING, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END

#define C_LOG_INFO_CONSOLE(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print_console(C_LOG_LEVEL_INFO, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END

#define C_LOG_DEBUG_CONSOLE(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print_console(C_LOG_LEVEL_DEBUG, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END

#define C_LOG_VERB_CONSOLE(...)

#ifdef DEBUG
#define C_LOG_DEBUG(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print(C_LOG_LEVEL_DEBUG, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END

#define C_LOG_VERB(...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print(C_LOG_LEVEL_VERB, C_LOG_TAG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
} C_STMT_END
#else
#define C_LOG_DEBUG(...)
#define C_LOG_VERB(...)
#endif

#define C_LOG_RAW(level, tag, file, line, fun, ...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print(level, tag, file, line, fun, __VA_ARGS__); \
} C_STMT_END

#define C_LOG_WRITE_FILE(level, ...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_raw(level, __VA_ARGS__); \
} C_STMT_END


#define C_LOG_RAW_CONSOLE(level, tag, file, line, fun, ...) \
C_STMT_START { \
    C_LOG_INIT_IF_NOT_INIT; \
    c_log_print_console(level, tag, file, line, fun, __VA_ARGS__); \
} C_STMT_END


/**
 * @brief 日志输出模式
 */
typedef enum
{
    C_LOG_TYPE_FILE = 0,
    C_LOG_TYPE_CONSOLE,
} CLogType;

/**
 * @brief 日志级别
 */
typedef enum
{
    C_LOG_LEVEL_ERROR       = 0,
    C_LOG_LEVEL_CRIT        = 1,
    C_LOG_LEVEL_WARNING     = 2,
    C_LOG_LEVEL_INFO        = 3,
    C_LOG_LEVEL_DEBUG       = 4,
    C_LOG_LEVEL_VERB        = 5,
} CLogLevel;

/**
 * @brief 初始化 log 参数
 *
 * @param level: 设置 log 输出级别
 * @param rotate: 是否切分文件
 * @param logSize: 每个日志文件的大小
 * @param dir: 日志文件存储文件夹路径
 * @param prefix: 日志文件名
 * @param suffix: 日志文件后缀名
 * @param hasTime: 文件名中是否带时间
 *
 * @return 成功: 0; 失败: -1
 */
bool c_log_init (CLogLevel level, cuint64 logSize, const cchar* dir, const cchar* prefix, const cchar* suffix, bool hasTime);

/**
 * 销毁 log 参数
 */
void c_log_destroy (void);

/**
 * @brief 输出日志到文件
 */
void c_log_print (CLogLevel level, const cchar* tag, const cchar* file, int line, const cchar* func, const cchar* fmt, ...);

/**
 * 输出日志到控制台
 */
void c_log_print_console (CLogLevel level, const cchar* tag, const cchar* file, int line, const cchar* func, const cchar* fmt, ...);

/**
 * 输出一行内容到文件，所见即所得，无任何附加信息（行末换行符号除外）
 */
void c_log_raw(CLogLevel level, const cchar* fmt, ...);

/**
 * @brief 是否完成初始化
 */
bool c_log_is_inited ();

C_END_EXTERN_C

#endif //CLIBRARY_LOG_H
