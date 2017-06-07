/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * This test program verifies that the gss_create_sec_context(),
 * gss_set_context_flags(), gss_init_sec_context(), and
 * gss_accept_sec_context() all interoperate correctly.
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
t_gss_handshake_create_init(gss_name_t target_name)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc accept_token;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_context = GSS_C_NO_CONTEXT;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_BOTH, &cred, NULL, NULL);
    check_gsserr("t_gss_handshake_create_init(0)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &init_context);
    check_gsserr("t_gss_handshake_create_init(1)", maj_stat, min_stat);

    /* Get the initial context token. */
    maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
                                    &init_context, target_name, mech, 0, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                    NULL, &init_token, NULL, NULL);

    check_gsserr("t_gss_handshake_create_init(2)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    /* Process this token into an acceptor context, then discard it. */
    maj_stat = gss_accept_sec_context(&min_stat, &accept_context,
                                      cred, &init_token,
                                      GSS_C_NO_CHANNEL_BINDINGS, NULL,
                                      NULL, &accept_token, NULL, NULL, NULL);
    check_gsserr("t_gss_handshake_create_init(3)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    (void)gss_release_buffer(&min_stat, &init_token);
    (void)gss_release_buffer(&min_stat, &accept_token);

    (void)gss_delete_sec_context(&min_stat, &accept_context, NULL);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}


static int
t_gss_handshake_create_accept(gss_name_t target_name)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc accept_token;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_context = GSS_C_NO_CONTEXT;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_BOTH, &cred, NULL, NULL);
    check_gsserr("t_gss_handshake_create_accept(0)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &accept_context);
    check_gsserr("t_gss_handshake_create_accept(1)", maj_stat, min_stat);

    /* Get the initial context token. */
    maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
                                    &init_context, target_name, mech, 0, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                    NULL, &init_token, NULL, NULL);

    check_gsserr("t_gss_handshake_create_accept(2)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    /* Process this token into an acceptor context, then discard it. */
    maj_stat = gss_accept_sec_context(&min_stat, &accept_context,
                                      cred, &init_token,
                                      GSS_C_NO_CHANNEL_BINDINGS, NULL,
                                      NULL, &accept_token, NULL, NULL, NULL);
    check_gsserr("t_gss_handshake_create_accept(3)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    (void)gss_release_buffer(&min_stat, &init_token);
    (void)gss_release_buffer(&min_stat, &accept_token);

    (void)gss_delete_sec_context(&min_stat, &accept_context, NULL);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}


static int
t_gss_handshake_create_both(gss_name_t target_name)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc accept_token;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_context = GSS_C_NO_CONTEXT;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_BOTH, &cred, NULL, NULL);
    check_gsserr("t_gss_handshake_create_both(0)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &init_context);
    check_gsserr("t_gss_handshake_create_both(1)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &accept_context);
    check_gsserr("t_gss_handshake_create_both(2)", maj_stat, min_stat);

    /* Get the initial context token. */
    maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
                                    &init_context, target_name, mech, 0, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                    NULL, &init_token, NULL, NULL);

    check_gsserr("t_gss_handshake_create_both(3)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    /* Process this token into an acceptor context, then discard it. */
    maj_stat = gss_accept_sec_context(&min_stat, &accept_context,
                                      cred, &init_token,
                                      GSS_C_NO_CHANNEL_BINDINGS, NULL,
                                      NULL, &accept_token, NULL, NULL, NULL);
    check_gsserr("t_gss_handshake_create_both(4)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    (void)gss_release_buffer(&min_stat, &init_token);
    (void)gss_release_buffer(&min_stat, &accept_token);

    (void)gss_delete_sec_context(&min_stat, &accept_context, NULL);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}


static int
t_gss_krb5_struct_empty_fireworks(gss_name_t target_name)
{
    OM_uint32 maj_stat = 0;
    OM_uint32 min_stat = 0;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_union_ctx_id_t union_ctx = NULL;
    krb5_context krb5_inner_context;
    krb5_error_code kerr;
    krb5_gss_ctx_id_rec *ctx;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc accept_token;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_context = GSS_C_NO_CONTEXT;

        maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                    GSS_C_BOTH, &cred, NULL, NULL);
        check_gsserr("t_gss_handshake_create_both(0)", maj_stat, min_stat);


    maj_stat = gss_create_sec_context(&min_stat, &context);
    check_gsserr("t_gss_create_context()", maj_stat, min_stat);
    assert(context != GSS_C_NO_CONTEXT);

    union_ctx = (gss_union_ctx_id_t)context;
    kerr = krb5_gss_init_context(&krb5_inner_context);
    if (kerr) {
        return 1;
    }

    ctx = (krb5_gss_ctx_id_rec *)calloc(sizeof(krb5_gss_ctx_id_rec), 1);
    if (ctx == NULL) {
        return 2;
    }

    ctx->magic = KG_CONTEXT;
    if (krb5_auth_con_init(krb5_inner_context, &ctx->auth_context))
        return 3;
    krb5_auth_con_setflags(krb5_inner_context, ctx->auth_context,
                           KRB5_AUTH_CONTEXT_DO_SEQUENCE);


    ctx->initiate = 1;
    union_ctx->internal_ctx_id = (gss_ctx_id_t) ctx;
    ctx->k5_context = krb5_inner_context;

    printf("%p %p\n", krb5_inner_context, ctx->k5_context);

    /* Get the initial context token. */
    maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
                                    &init_context, target_name, mech, 0, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                    NULL, &init_token, NULL, NULL);

    check_gsserr("t_gss_handshake_create_both(3)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);
    assert(init_token.length != 0);

    /* Process this token into an acceptor context, then discard it. */
    maj_stat = gss_accept_sec_context(&min_stat, &accept_context,
                                      cred, &init_token,
                                      GSS_C_NO_CHANNEL_BINDINGS, NULL,
                                      NULL, &accept_token, NULL, NULL, NULL);
    check_gsserr("t_gss_handshake_create_both(4)", maj_stat, min_stat);
    assert(maj_stat == GSS_S_COMPLETE);

    (void)gss_release_buffer(&min_stat, &init_token);
    (void)gss_release_buffer(&min_stat, &accept_token);

    (void)gss_delete_sec_context(&min_stat, &accept_context, NULL);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}

int
main(int argc, char *argv[])
{
    int ret_val = 0;
    gss_name_t target_name;
    OM_uint32 min_stat;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s targetname\n", argv[0]);
        return 1;
    }
    target_name = import_name(argv[1]);

    assert(t_gss_handshake_create_init(target_name) == 0);
    printf("t_gss_handshake_create_init... ok\n");

    assert(t_gss_handshake_create_accept(target_name) == 0);
    printf("t_gss_handshake_create_accept.. ok\n");

    assert(t_gss_handshake_create_both(target_name) == 0);
    printf("t_gss_handshake_create_both... ok\n");

    ret_val = t_gss_krb5_struct_empty_fireworks(target_name);
    printf("%d\n", ret_val);
    assert(ret_val == 0);
    printf("t_gss_krb5_struct_empty_fireworks()... ok\n");

    (void)gss_release_name(&min_stat, &target_name);
}
