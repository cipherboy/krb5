/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/*
 * This test program verifies that the new chanel binding extensions work as
 * specified in:
 *
 * https://tools.ietf.org/html/draft-ietf-kitten-channel-bound-flag-01
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
t_gss_channel_bindings_check(gss_name_t target_name,
                             OM_uint32 req_flags,
                             OM_uint32 init_ret_flags_understood,
                             OM_uint32 accept_ret_flags_understood,
                             gss_channel_bindings_t cbindings,
                             OM_uint32 e_init_status,
                             OM_uint32 e_accept_status,
                             OM_uint32 m_init_ret_flags,
                             OM_uint32 e_init_ret_flags,
                             OM_uint32 m_accept_ret_flags,
                             OM_uint32 e_accept_ret_flags)
{
    /* Check that both init/accept_sec_context() accept empty sec contexts */
    OM_uint32 maj_stat;
    OM_uint32 min_stat;
    OM_uint32 init_ret_flags;
    OM_uint32 accept_ret_flags;
    OM_uint32 init_maj_stat = GSS_S_CONTINUE_NEEDED;
    OM_uint32 init_min_stat = 0;
    OM_uint32 accept_maj_stat = GSS_S_CONTINUE_NEEDED;
    OM_uint32 accept_min_stat = 0;
    gss_OID mech = &mech_krb5;
    gss_buffer_desc init_token;
    gss_buffer_desc accept_token;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t init_context = GSS_C_NO_CONTEXT;
    gss_ctx_id_t accept_context = GSS_C_NO_CONTEXT;

    maj_stat = gss_acquire_cred(&min_stat, GSS_C_NO_NAME, 0, GSS_C_NO_OID_SET,
                                GSS_C_BOTH, &cred, NULL, NULL);
    check_gsserr("t_gss_handshake_create_both(0)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &init_context);
    check_gsserr("t_gss_handshake_create_both(1)", maj_stat, min_stat);

    maj_stat = gss_create_sec_context(&min_stat, &accept_context);
    check_gsserr("t_gss_handshake_create_both(4)", maj_stat, min_stat);

    maj_stat = gss_set_context_flags(&min_stat, init_context, req_flags,
                                     init_ret_flags_understood);
    check_gsserr("t_gss_handshake_create_both(2)", maj_stat, min_stat);

    maj_stat = gss_set_context_flags(&min_stat, accept_context, req_flags,
                                     accept_ret_flags_understood);
    check_gsserr("t_gss_handshake_create_both(3)", maj_stat, min_stat);

    init_token.length = 0;
    init_token.value = NULL;
    accept_token.length = 0;
    accept_token.value = NULL;

    do {
        init_maj_stat = gss_init_sec_context(&init_min_stat,
                                             GSS_C_NO_CREDENTIAL,
                                             &init_context, target_name, mech,
                                             0, 0, cbindings, &accept_token,
                                             NULL, &init_token,
                                             &init_ret_flags, NULL);

        if (accept_maj_stat != GSS_S_CONTINUE_NEEDED)
            break;

        accept_maj_stat = gss_accept_sec_context(&accept_min_stat, 
                                                 &accept_context,
                                                 cred, &init_token,
                                                 cbindings, NULL, NULL,
                                                 &accept_token,
                                                 &accept_ret_flags, NULL,
                                                 NULL);

        if (init_maj_stat != GSS_S_CONTINUE_NEEDED)
            break;
    } while (1);

    if (e_init_status == GSS_S_COMPLETE && init_maj_stat != e_init_status)
        check_gsserr("t_gss_handshake_create_both(4)", init_maj_stat, init_min_stat);

    if (init_maj_stat != e_init_status)
        return 1;

    if (e_accept_status == GSS_S_COMPLETE && accept_maj_stat != e_accept_status)
        check_gsserr("t_gss_handshake_create_both(5)", accept_maj_stat, accept_min_stat);

    if (accept_maj_stat != e_accept_status)
        return 2;

    if ((init_ret_flags & m_init_ret_flags) != e_init_ret_flags)
        return 3;

    if ((accept_ret_flags & m_accept_ret_flags) != e_accept_ret_flags)
        return 4;

    (void)gss_release_cred(&min_stat, &cred);

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
    OM_uint32 mask;
    gss_channel_bindings_t cb;
    int call_val = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s targetname\n", argv[0]);
        return 1;
    }
    target_name = import_name(argv[1]);

    cb = calloc(sizeof(struct gss_channel_bindings_struct), 1);
    assert(cb != NULL);

    cb->initiator_addrtype = GSS_C_AF_NULLADDR;
    cb->initiator_address.length = 0;
    cb->acceptor_addrtype= GSS_C_AF_NULLADDR;
    cb->acceptor_address.length = 0;
    cb->application_data.length = 4;
    cb->application_data.value = "test";

    mask = GSS_C_MUTUAL_FLAG | GSS_C_CHANNEL_BOUND_FLAG;

    call_val = t_gss_channel_bindings_check(
        target_name,
        0,
        0,
        0,
        GSS_C_NO_CHANNEL_BINDINGS,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        mask,
        0,
        mask,
        0);
    assert(call_val == 0);

    call_val = t_gss_channel_bindings_check(
        target_name,
        GSS_C_MUTUAL_FLAG,
        mask,
        mask,
        GSS_C_NO_CHANNEL_BINDINGS,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        mask,
        GSS_C_MUTUAL_FLAG,
        mask,
        GSS_C_MUTUAL_FLAG);
    assert(call_val == 0);

    call_val = t_gss_channel_bindings_check(
        target_name,
        0,
        mask,
        mask,
        cb,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        mask,
        0,
        mask,
        GSS_C_CHANNEL_BOUND_FLAG);
    assert(call_val == 0);

    call_val = t_gss_channel_bindings_check(
        target_name,
        GSS_C_MUTUAL_FLAG,
        GSS_C_MUTUAL_FLAG,
        GSS_C_MUTUAL_FLAG,
        cb,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        mask,
        GSS_C_MUTUAL_FLAG,
        mask,
        mask);
    assert(call_val == 0);

    call_val = t_gss_channel_bindings_check(
        target_name,
        mask,
        GSS_C_MUTUAL_FLAG,
        GSS_C_MUTUAL_FLAG,
        GSS_C_NO_CHANNEL_BINDINGS,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        mask,
        GSS_C_MUTUAL_FLAG,
        mask,
        GSS_C_MUTUAL_FLAG);
    assert(call_val == 0);

    call_val = t_gss_channel_bindings_check(
        target_name,
        mask,
        mask,
        mask,
        cb,
        GSS_S_COMPLETE,
        GSS_S_COMPLETE,
        mask,
        GSS_C_MUTUAL_FLAG,
        mask,
        mask);
    assert(call_val == 0);

    (void)gss_release_name(&min_stat, &target_name);

    return 0;
}
