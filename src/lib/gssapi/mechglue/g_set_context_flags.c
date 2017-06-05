/* #pragma ident	                                                         */

/*
 *  glue routine for gss_set_context_flags
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
 * Section 2.2
 * 
 * See src/lib/gssapi/generic/gssapi_ext.h for type definitions.
 */
OM_uint32 KRB5_CALLCONV
gss_set_context_flags(minor_status,
                      context,
                      req_flags,
                      ret_flags)

OM_uint32    *minor_status;
gss_ctx_id_t *context;
uint64_t      req_flags;
uint64_t      ret_flags;
{
    stub_gss_ctx_id_rec *ctx;

    if (ctx_handle == NULL) {
        return GSS_S_FAILURE;
    }

    ctx = (stub_gss_ctx_id_rec *)context;

    if (ctx->magic_num != STUB_MAGIC_ID) {
        return GSS_S_FAILURE;
    }

    ctx->req_flags = req_flags;
    ctx->ret_flags = ret_flags;

    return GSS_S_COMPLETE;
}

#endif
