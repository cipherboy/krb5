/* #pragma ident	                                                         */

/*
 *  glue routine for gss_create_sec_context
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>
#include <time.h>

#ifndef LEAN_CLIENT


/*
 * Defined:
 * https://tools.ietf.org/html/draft-ietf-kitten-channel-bound-flag-01
 *
 * Section 2.1
 * 
 * See src/lib/gssapi/generic/gssapi_ext.h for type definitions.
 */
OM_uint32 KRB5_CALLCONV
gss_create_sec_context(OM_uint32 *minor_status, gss_ctx_id_t *context)
{
    gss_union_ctx_id_t union_ctx;
    stub_gss_ctx_id_rec *ctx;

    if (context == NULL)
        return GSS_S_FAILURE;

    *minor_status = 0;

    union_ctx = calloc(sizeof(gss_union_ctx_id_desc), 1);
    if (union_ctx == NULL)
        return GSS_S_UNAVAILABLE;

    ctx = calloc(sizeof(stub_gss_ctx_id_rec), 1);
    if (ctx == NULL) {
        free(union_ctx);
        return GSS_S_UNAVAILABLE;
    }

    ctx->magic_num = STUB_MAGIC_ID;

    union_ctx->loopback = union_ctx;
    union_ctx->mech_type = GSS_C_NO_OID;
    union_ctx->internal_ctx_id = (gss_ctx_id_t)ctx;

    *context = (gss_ctx_id_t)union_ctx;

    return GSS_S_COMPLETE;
}

#endif
