/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "k5-int.h"
#include "gssapiP_krb5.h"

#include <stdlib.h>
#include <assert.h>


OM_uint32 KRB5_CALLCONV
krb5_gss_set_context_flags(OM_uint32 *minor_status, gss_ctx_id_t context, uint64_t req_flags, uint64_t ret_flags)
{
    krb5_gss_ctx_id_t external_context;

    if (context == GSS_C_NO_CONTEXT) {
        return GSS_S_FAILURE | GSS_S_NO_CONTEXT;
    }

    external_context = (krb5_gss_ctx_id_t)context;
    if (external_context->magic != KG_CONTEXT) {
        return GSS_S_FAILURE | GSS_S_NO_CONTEXT;
    }

    if (req_flags == 0) {
        return GSS_S_COMPLETE;
    }

    external_context->gss_flags = req_flags & (GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG |
                                  GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG |
                                  GSS_C_SEQUENCE_FLAG | GSS_C_DELEG_FLAG |
                                  GSS_C_DCE_STYLE | GSS_C_IDENTIFY_FLAG |
                                  GSS_C_EXTENDED_ERROR_FLAG);
    external_context->gss_flags |= GSS_C_TRANS_FLAG;
    if (req_flags & GSS_C_DCE_STYLE)
        external_context->gss_flags |= GSS_C_MUTUAL_FLAG;

    return GSS_S_COMPLETE;
}
