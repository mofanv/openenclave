// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "enclave.h"
#include "hostthread.h"
#include "repo_config_info.h"

#define LOGGING_FORMAT_STRING "%02d:%02d:%02d (%s)[%-5s]%s"
static char* log_level_strings[OE_LOG_LEVEL_MAX] = {"",
                                                    "FATAL",
                                                    "ERROR",
                                                    "WARN",
                                                    "INFO"};
static oe_mutex g_log_lock = OE_H_MUTEX_INITIALIZER;
static const char* g_log_file_name = NULL;
static log_level_t g_log_level = OE_LOG_LEVEL_ERROR;
static bool g_initialized = false;

static log_level_t env2log_level(void)
{
    log_level_t level = OE_LOG_LEVEL_ERROR;
    const char* level_str = getenv("OE_LOG_LEVEL");

    if (level_str == NULL)
    {
        goto done;
    }
    else if (strcasecmp(level_str, "INFO") == 0)
    {
        level = OE_LOG_LEVEL_INFO;
    }
    else if (strcasecmp(level_str, "WARNING") == 0)
    {
        level = OE_LOG_LEVEL_WARNING;
    }
    else if (strcasecmp(level_str, "ERROR") == 0)
    {
        level = OE_LOG_LEVEL_ERROR;
    }
    else if (strcasecmp(level_str, "FATAL") == 0)
    {
        level = OE_LOG_LEVEL_FATAL;
    }

done:
    return level;
}

static void initialize_log_config()
{
    if (!g_initialized)
    {
        // inititalize if not already
        g_log_level = env2log_level();
        g_log_file_name = getenv("OE_LOG_DEVICE");
        g_initialized = true;
    }
}

static void log_session_header()
{
    if (!g_log_file_name)
        return;

    // Take the log file lock.
    if (oe_mutex_lock(&g_log_lock) == OE_OK)
    {
        FILE* log_file = NULL;
        log_file = fopen(g_log_file_name, "a");
        if (log_file == NULL)
        {
            fprintf(stderr, "Failed to create logfile %s\n", g_log_file_name);
            oe_mutex_unlock(&g_log_lock);
            return;
        }

        fprintf(
            log_file,
            "================= New logging session =================\n");
        fprintf(
            log_file,
            "https://github.com/Microsoft/openenclave branch:%s\n",
            OE_REPO_BRANCH_NAME ? OE_REPO_BRANCH_NAME : "Unavailable");
        fprintf(
            log_file,
            "Last commit:%s\n",
            OE_REPO_LAST_COMMIT ? OE_REPO_LAST_COMMIT : "Unavailable");

        fflush(log_file);
        fclose(log_file);
        oe_mutex_unlock(&g_log_lock);
    }
}

oe_result_t oe_log_enclave_init(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    log_level_t level = g_log_level;

    initialize_log_config();

    // Populate arg fields.
    oe_log_filter_t* arg = calloc(1, sizeof(oe_log_filter_t));
    if (arg == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }
    arg->path = enclave->path;
    arg->level = level;
    // Call enclave
    result = oe_ecall(enclave, OE_ECALL_LOG_INIT, (uint64_t)arg, NULL);
    if (result != OE_OK)
        goto done;

    result = OE_OK;
done:
    return result;
}

void oe_log(log_level_t level, const char* fmt, ...)
{
    if (g_initialized)
    {
        if (level > g_log_level)
            return;
    }

    if (!fmt)
        return;

    oe_log_args_t args;
    args.level = level;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(args.message, OE_LOG_MESSAGE_LEN_MAX, fmt, ap);
    va_end(ap);
    _log(false, &args);
}

// This is an expensive operation, it involves acquiring lock
// and file operation.
void _log(bool is_enclave, oe_log_args_t* args)
{
    time_t t = time(NULL);
    struct tm* lt = localtime(&t);

    if (!g_initialized)
    {
        initialize_log_config();
        log_session_header();
    }
    if (g_initialized)
    {
        if (args->level > g_log_level)
            return;
    }

    if (!g_log_file_name)
    {
        printf(
            LOGGING_FORMAT_STRING,
            lt->tm_hour,
            lt->tm_min,
            lt->tm_sec,
            (is_enclave ? "E" : "H"),
            log_level_strings[args->level],
            args->message);
    }
    else
    {
        // Take the log file lock.
        if (oe_mutex_lock(&g_log_lock) == OE_OK)
        {
            FILE* log_file = NULL;
            log_file = fopen(g_log_file_name, "a");
            if (log_file == NULL)
            {
                fprintf(
                    stderr, "Failed to create logfile %s\n", g_log_file_name);
                oe_mutex_unlock(&g_log_lock);
                return;
            }

            fprintf(
                log_file,
                LOGGING_FORMAT_STRING,
                lt->tm_hour,
                lt->tm_min,
                lt->tm_sec,
                (is_enclave ? "E" : "H"),
                log_level_strings[args->level],
                args->message);
            fflush(log_file);
            fclose(log_file);

            // Release the log file lock.
            oe_mutex_unlock(&g_log_lock);
        }
    }
}

log_level_t get_current_logging_level(void)
{
    return g_log_level;
}
