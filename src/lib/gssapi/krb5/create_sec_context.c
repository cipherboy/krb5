/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "k5-int.h"
#include "gssapiP_krb5.h"

#include <assert.h>


OM_uint32 KRB5_CALLCONV
krb5_gss_create_sec_context(OM_uint32 *minor_status, gss_ctx_id_t *context)
{
    krb5_gss_ctx_id_rec *ctx;
    if (context == NULL) {
        return GSS_S_FAILURE;
    }

    ctx = calloc(sizeof(krb5_gss_ctx_id_rec), 1);
    if (ctx == NULL) {
        return GSS_S_FAILURE;
    }

    ctx->magic = KG_CONTEXT;

    *context = (gss_ctx_id_t) ctx;

    assert(KRB5INT_CHK_EMPTY(ctx));

    return GSS_S_COMPLETE;
}
