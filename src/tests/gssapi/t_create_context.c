/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * This test program verifies that the gss_create_sec_context() can create
 * stub contexts, that gss_set_context_flags() can interpret them, and that
 * gss_delete_sec_context() can correctly free the structures.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "k5-int.h"
#include "k5-platform.h"
#include "common.h"
#include "mglueP.h"
#include "gssapiP_krb5.h"
#include "gssapi_ext.h"

static int
t_gss_create_context()
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_union_ctx_id_t union_check;
    stub_gss_ctx_id_rec *check;
    gss_ctx_id_t *context_handle = NULL;

    maj_stat = gss_create_sec_context(&min_stat, NULL);
    assert(maj_stat != GSS_S_COMPLETE);

    maj_stat = gss_create_sec_context(&min_stat, &context);
    check_gsserr("t_gss_create_context()", maj_stat, min_stat);
    assert(context != GSS_C_NO_CONTEXT);

    union_check = (gss_union_ctx_id_t)context;
    assert(union_check != NULL);
    assert(union_check == union_check->loopback);
    assert(union_check->internal_ctx_id == NULL);
    assert(union_check->initial_ctx_id != NULL);

    check = (stub_gss_ctx_id_rec *)union_check->initial_ctx_id;
    assert(check->magic_num == STUB_MAGIC_ID);
    assert(check->req_flags == 0);
    assert(check->ret_flags == 0);

    free(check);
    free(union_check);
    check = NULL;

    maj_stat = gss_create_sec_context(&min_stat, context_handle);
    assert(maj_stat != GSS_S_COMPLETE);

    context_handle = malloc(sizeof(gss_ctx_id_t));
    if (context_handle == NULL) {
        fprintf(stderr, "MALLOC failed. OOM.\n");
        return 1;
    }

    maj_stat = gss_create_sec_context(&min_stat, context_handle);
    check_gsserr("t_gss_create_context()", maj_stat, min_stat);

    assert(*context_handle != NULL);

    union_check = (gss_union_ctx_id_t)(*context_handle);
    assert(union_check != NULL);
    assert(union_check == union_check->loopback);
    assert(union_check->internal_ctx_id == NULL);
    assert(union_check->initial_ctx_id != NULL);

    check = (stub_gss_ctx_id_rec *)union_check->initial_ctx_id;
    assert(check->magic_num == STUB_MAGIC_ID);
    assert(check->req_flags == 0);
    assert(check->ret_flags == 0);

    free(check);
    free(union_check);
    free(context_handle);

    return 0;
}

static int
t_gss_set_context_flags()
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_union_ctx_id_t union_check;
    stub_gss_ctx_id_rec *check;

    maj_stat = gss_set_context_flags(&min_stat, context, 1, 2);
    assert(maj_stat != GSS_S_COMPLETE);

    maj_stat = gss_create_sec_context(&min_stat, &context);
    check_gsserr("t_gss_set_context_flags()", maj_stat, min_stat);

    maj_stat = gss_set_context_flags(&min_stat, context, 1, 2);
    check_gsserr("t_gss_set_context_flags()", maj_stat, min_stat);

    union_check = (gss_union_ctx_id_t)context;
    assert(union_check != NULL);
    assert(union_check == union_check->loopback);
    assert(union_check->internal_ctx_id == NULL);
    assert(union_check->initial_ctx_id != NULL);

    check = (stub_gss_ctx_id_rec *)union_check->initial_ctx_id;
    assert(check != NULL);
    assert(check->magic_num == STUB_MAGIC_ID);
    assert(check->req_flags == 1);
    assert(check->ret_flags == 2);

    free(check);
    free(union_check);

    context = NULL;
    maj_stat = gss_set_context_flags(&min_stat, context, 1, 2);
    assert(maj_stat != GSS_S_COMPLETE);

    return 0;
}

static int
t_gss_create_delete_integration()
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_buffer_desc out_buf;

    maj_stat = gss_create_sec_context(&min_stat, &context);
    check_gsserr("t_gss_create_delete_integration()", maj_stat, min_stat);

    assert(context != GSS_C_NO_CONTEXT);

    maj_stat = gss_delete_sec_context(&min_stat, &context, &out_buf);
    check_gsserr("t_gss_create_delete_integration()", maj_stat, min_stat);

    assert(out_buf.length == 0);

    return 0;
}


int
main(int argc, char *argv[])
{
    assert(t_gss_create_context() == 0);
    printf("t_gss_create_context()... ok\n");

    assert(t_gss_set_context_flags() == 0);
    printf("t_gss_set_context_flags()... ok\n");

    assert(t_gss_create_delete_integration() == 0);
    printf("t_gss_create_delete_integration()... ok\n");
}
