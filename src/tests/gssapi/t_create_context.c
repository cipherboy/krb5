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
    stub_gss_ctx_id_rec *check;
    gss_ctx_id_t *context_handle = NULL;

    maj_stat = gss_create_sec_context(&min_stat, NULL);
    assert(maj_stat == GSS_S_FAILURE);

    maj_stat = gss_create_sec_context(&min_stat, &context);
    check_gsserr("t_gss_create_context()", maj_stat, min_stat);
    assert(context != GSS_C_NO_CONTEXT);
    check = (stub_gss_ctx_id_rec *)context;
    assert(check != NULL);
    assert(check->magic_num == STUB_MAGIC_ID);
    assert(check->req_flags == 0);
    assert(check->ret_flags == 0);

    free(check);
    check = NULL;

    maj_stat = gss_create_sec_context(&min_stat, context_handle);
    assert(maj_stat = GSS_S_FAILURE);

    context_handle = malloc(sizeof(gss_ctx_id_t));
    if (context_handle == NULL) {
        return 1;
    }

    maj_stat = gss_create_sec_context(&min_stat, context_handle);
    check_gsserr("t_gss_create_context()", maj_stat, min_stat);

    assert(*context_handle != NULL);
    check = (stub_gss_ctx_id_rec *)(*context_handle);
    assert(check != NULL);
    assert(check->magic_num == STUB_MAGIC_ID);
    assert(check->req_flags == 0);
    assert(check->ret_flags == 0);

    free(check);
    free(context_handle);

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
