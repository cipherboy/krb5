/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "k5-int.h"
#include "gssapiP_krb5.h"

#include <assert.h>


OM_uint32 KRB5_CALLCONV
krb5_gss_create_sec_context(OM_uint32 *minor_status, gss_ctx_id_t *context)
{
    /*krb5_error_code kerr;

    krb5_context new_context;
    if (*context == GSS_C_NO_CONTEXT) {
        kerr = krb5_gss_init_context(&new_context);
        if (kerr) {
            *minor_status = kerr;
            return GSS_S_FAILURE;
        }
        if (GSS_ERROR(kg_sync_ccache_name(new_context, minor_status))) {
            save_error_info(*minor_status, new_context);
            krb5_free_context(new_context);
            return GSS_S_FAILURE;
        }
    } else {
        context = ((krb5_gss_ctx_id_rec *)*context_handle)->k5_context;
    }

    krb5_gss_init_context()*/
    return 0;
}
