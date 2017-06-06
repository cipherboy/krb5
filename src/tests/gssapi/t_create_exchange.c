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

#include "common.h"

static int
t_gss_handshake_no_flags(gss_name_t target_name)
{
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_buffer_desc accept_token;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_context = GSS_C_NO_CONTEXT;

    maj_stat = gss_create_sec_context(&min_stat, &init_context);
    check_gsserr("t_gss_handshake_no_flags()", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &accept_context);
    check_gsserr("t_gss_handshake_no_flags()", maj_stat, min_stat);

    /* Get the initial context token. */
    maj_stat = gss_init_sec_context(&min_stat, GSS_C_NO_CREDENTIAL,
                                    &init_context, target_name, mech, 0, 0,
                                    GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                                    NULL, &init_token, NULL, NULL);

    check_gsserr("t_gss_handshake_no_flags()", maj_stat, min_stat);
    assert(maj_stat == GSS_S_CONTINUE_NEEDED);

    /* Process this token into an acceptor context, then discard it. */
    maj_stat = gss_accept_sec_context(&min_stat, &accept_context,
                                      GSS_C_NO_CREDENTIAL, &init_token,
                                      GSS_C_NO_CHANNEL_BINDINGS, NULL,
                                      NULL, &accept_token, NULL, NULL, NULL);
    check_gsserr("t_gss_handshake_no_flags()", maj_stat, min_stat);

    (void)gss_release_buffer(&min_stat, &init_token);
    (void)gss_release_buffer(&min_stat, &accept_token);

    (void)gss_delete_sec_context(&min_stat, &accept_context, NULL);
    (void)gss_delete_sec_context(&min_stat, &init_context, NULL);
    return 0;
}

int
main(int argc, char *argv[])
{
    gss_name_t target_name;
    OM_uint32 min_stat;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s targetname\n", argv[0]);
        return 1;
    }
    target_name = import_name(argv[1]);

    assert(t_gss_handshake_no_flags(target_name) == 0);
    printf("t_gss_handshake_no_flags... ok\n");

    (void)gss_release_name(&min_stat, &target_name);
}
