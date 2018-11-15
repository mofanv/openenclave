// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OETRACE_H
#define _OETRACE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

// logging flags
#define OE_LOG_FLAGS_NONE 0x00000000
#define OE_LOG_FLAGS_ATTESTATION 0x00000001
#define OE_LOG_FLAGS_GET_REPORT 0x00000002
#define OE_LOG_FLAGS_VERIFY_REPORT 0x00000004
#define OE_LOG_FLAGS_COMMON 0x00000008
#define OE_LOG_FLAGS_CERT 0x00000010
#define OE_LOG_FLAGS_TOOLS 0x00000020
#define OE_LOG_FLAGS_CRYPTO 0x00000040
#define OE_LOG_FLAGS_SGX_SPECIFIC 0x00000100
#define OE_LOG_FLAGS_IMAGE_LOADING 0x00000200
#define OE_LOG_FLAGS_OTHERS 0x00000400
#define OE_LOG_FLAGS_ALL 0xffffffff

typedef enum _log_level_ {
    OE_LOG_LEVEL_NONE = 0,
    OE_LOG_LEVEL_FATAL,
    OE_LOG_LEVEL_ERROR,
    OE_LOG_LEVEL_WARNING,
    OE_LOG_LEVEL_INFO,
    OE_LOG_LEVEL_MAX
} log_level_t;

/* Maximum log length */
#define OE_LOG_MESSAGE_LEN_MAX 256
#define MAX_FILENAME_LEN 256

typedef struct _oe_log_filter
{
    const char* path;
    bool debug_enclave;
    uint64_t flags;
    log_level_t level;
} oe_log_filter_t;

typedef struct _oe_log_args
{
    uint64_t flags;
    log_level_t level;
    char message[OE_LOG_MESSAGE_LEN_MAX];
} oe_log_args_t;

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
OE_EXTERNC_BEGIN
oe_result_t _handle_oelog_init(uint64_t arg);
oe_result_t oe_log(uint64_t flag, log_level_t level, const char* fmt, ...);
log_level_t get_current_logging_level(void);
OE_EXTERNC_END
#else
#include <stdio.h>
OE_EXTERNC_BEGIN
oe_result_t oe_log_enclave_init(oe_enclave_t* enclave, bool debug_enclave);
void oe_log(uint64_t flags, log_level_t level, const char* fmt, ...);
log_level_t get_current_logging_level(void);
void _log(bool is_enclave, oe_log_args_t* args);
OE_EXTERNC_END
#endif

#define OE_TRACE(level, ...)                    \
    do                                          \
    {                                           \
        oe_log(trace_flag, level, __VA_ARGS__); \
    } while (0)

#define OE_TRACE_FATAL(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_FATAL,      \
        fmt " @%s %s:%d\n",      \
        ##__VA_ARGS__,           \
        __FILE__,                \
        __FUNCTION__,            \
        __LINE__)

#define OE_TRACE_ERROR(fmt, ...) \
    OE_TRACE(                    \
        OE_LOG_LEVEL_ERROR,      \
        fmt " @%s %s:%d\n",      \
        ##__VA_ARGS__,           \
        __FILE__,                \
        __FUNCTION__,            \
        __LINE__)

#define OE_TRACE_WARNING(fmt, ...) \
    OE_TRACE(                      \
        OE_LOG_LEVEL_WARNING,      \
        fmt "[%s %s:%d]\n",        \
        ##__VA_ARGS__,             \
        __FILE__,                  \
        __FUNCTION__,              \
        __LINE__)

#define OE_TRACE_INFO(fmt, ...) \
    OE_TRACE(                   \
        OE_LOG_LEVEL_INFO,      \
        fmt "[%s %s:%d]\n",     \
        ##__VA_ARGS__,          \
        __FILE__,               \
        __FUNCTION__,           \
        __LINE__)

#endif
