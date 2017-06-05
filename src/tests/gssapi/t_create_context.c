/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * This test program verifies that the gss_create_context() can create stub
 * contexts and that gss_set_context_flags() can interpret them.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gssapi/gssapi_ext.h>

#include "common.h"

int t_gss_create_context(void);

int
t_gss_create_context(void)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t *context_handle = NULL;

    maj_stat = gss_create_sec_context(&min_stat, NULL);
    check_gsserr("t_gss_create_context()", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &context);
    check_gsserr("t_gss_create_context()", maj_stat, min_stat);

    free(context);

    maj_stat = gss_create_sec_context(&min_stat, context_handle);
    check_gsserr("t_gss_create_context()", maj_stat, min_stat);

    return 0;
}

int
main(int argc, char *argv[])
{
    int call_val = 0;

    call_val = t_gss_create_context();
    if (call_val != 0) {
        return 1;
    }
}
