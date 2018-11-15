// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/bits/types.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>

#define DEFAULT_LOGGING_LEVEL OE_LOG_LEVEL_NONE

static oe_log_filter_t g_active_log_filter = {0};
static log_level_t g_host_level;
static char g_logging_filename[MAX_FILENAME_LEN];
static bool g_logging_enabled = false;
static bool g_debug_enclave = false;

const char* get_filename_from_path(const char* path)
{
    for (size_t i = oe_strlen(path) - 1; i >= 0; i--)
    {
        if (path[i] == '/')
        {
            return &path[i + 1];
        }
    }
    return path;
}

bool is_enclave_debuggable()
{
    bool ret = false;
    oe_result_t result = 0;
    uint64_t report_buffer_size = OE_MAX_REPORT_SIZE;
    uint8_t *report_buffer = NULL;
    const sgx_report_t* sgx_report = NULL;
    oe_report_header_t* header = NULL;

    report_buffer = (uint8_t*)oe_malloc(OE_MAX_REPORT_SIZE);
    if (report_buffer == NULL)
        goto done;

    // get a report on the enclave itself for enclave identity information
    report_buffer_size = OE_MAX_REPORT_SIZE;
    result = oe_get_report(0, NULL, 0, NULL, 0, report_buffer, &report_buffer_size);
    if (result != OE_OK)
        goto done;

    header = (oe_report_header_t*)report_buffer;
    sgx_report = (const sgx_report_t*)header->report;
    ret = (sgx_report->body.attributes.flags & SGX_FLAGS_DEBUG) != 0;

done:
    if (report_buffer)
        oe_free(report_buffer);

    return ret;
}

/*
**==============================================================================
**
** _handle_oelog_init()
**
** Handle the OE_ECALL_LOG_INIT from host and initialize SDK logging
*configuration
**
**==============================================================================
*/
oe_result_t _handle_oelog_init(uint64_t arg)
{
    oe_result_t result = OE_FAILURE;
    const char* filename = NULL;
    oe_log_filter_t* filter = (oe_log_filter_t*)arg;

    if (filter == NULL)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!oe_is_outside_enclave((void*)filter, sizeof(oe_log_filter_t)))
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!oe_is_outside_enclave((void*)(filter->path), MAX_FILENAME_LEN))
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Copy structure into enclave memory */
    oe_memcpy(&g_active_log_filter, filter, sizeof(oe_log_filter_t));
    g_active_log_filter.path = NULL;

    filename = get_filename_from_path(filter->path);
    if (filename)
    {
        oe_strlcpy(g_logging_filename, filename, sizeof(g_logging_filename));
    }
    else
    {
        oe_memset(g_logging_filename, 0, sizeof(g_logging_filename));
    }

    g_host_level = g_active_log_filter.level;

    // For production enclaves, default value is set to *_NONE
    g_debug_enclave = is_enclave_debuggable();
    if (!g_debug_enclave)
    {
        g_active_log_filter.level = DEFAULT_LOGGING_LEVEL;
    }
    g_logging_enabled = g_debug_enclave;

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_log(log_level_t level, const char* fmt, ...)
{
    oe_result_t result = OE_FAILURE;
    oe_log_args_t* args = NULL;

    if (g_debug_enclave && g_logging_enabled)
    {
        g_active_log_filter.level = g_host_level;
    }
    else
    {
        g_active_log_filter.level = DEFAULT_LOGGING_LEVEL;
    }

    // Check if this message should be skipped
    if (level > g_active_log_filter.level)
    {
        result = OE_OK;
        goto done;
    }
    // Validate input
    if (!fmt)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    // Prepare a log record for sending to the host for logging
    if (!(args = oe_host_malloc(sizeof(oe_log_args_t))))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    oe_snprintf(
        args->message, OE_LOG_MESSAGE_LEN_MAX, "%s:", g_logging_filename);

    args->level = level;
    oe_va_list ap;
    oe_va_start(ap, fmt);
    int n = oe_vsnprintf(
        &args->message[oe_strlen(g_logging_filename) + 1],
        OE_LOG_MESSAGE_LEN_MAX,
        fmt,
        ap);
    oe_va_end(ap);
    if (n < 0)
        goto done;

    // send over to the host
    if (oe_ocall(OE_OCALL_LOG, (uint64_t)args, NULL) != OE_OK)
        goto done;

    result = OE_OK;
done:
    if (args)
    {
        oe_host_free(args);
    }
    return result;
}

log_level_t get_current_logging_level(void)
{
    return g_active_log_filter.level;
}

void oe_enable_sdk_logging(bool enabled)
{
    g_logging_enabled = enabled;
}
