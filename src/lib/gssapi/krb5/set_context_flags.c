/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "k5-int.h"
#include "gssapiP_krb5.h"

#include <stdlib.h>

OM_uint32 KRB5_CALLCONV
krb5_gss_set_context_flags(OM_uint32 *minor_status, gss_ctx_id_t context,
                           uint64_t req_flags, uint64_t ret_flags_understood)
{
    krb5_gss_ctx_id_t ctx;

    if (context == GSS_C_NO_CONTEXT)
        return GSS_S_FAILURE | GSS_S_NO_CONTEXT;

    if (minor_status != NULL)
        *minor_status = 0;

    ctx = (krb5_gss_ctx_id_t)context;
    if (ctx->magic != KG_CONTEXT)
        return GSS_S_FAILURE | GSS_S_NO_CONTEXT;

    ctx->req_flags = req_flags;
    ctx->ret_flags_understood = ret_flags_understood;

    return GSS_S_COMPLETE;
}
