/* #pragma ident	                                                    */

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

/*
 * Defined:
 * https://tools.ietf.org/html/draft-ietf-kitten-channel-bound-flag-01
 *
 * Section 2.2
 *
 * See src/lib/gssapi/generic/gssapi_ext.h for type definitions.
 */
OM_uint32 KRB5_CALLCONV
gss_set_context_flags(OM_uint32 *minor_status, gss_ctx_id_t context,
                      uint64_t req_flags, uint64_t ret_flags_understood)
{
    gss_union_ctx_id_t union_ctx;

    if (context == NULL)
        return GSS_S_FAILURE;

    union_ctx = (gss_union_ctx_id_t)context;
    if (GSSINT_CHK_LOOP(union_ctx))
        return GSS_S_FAILURE;

    union_ctx->req_flags = req_flags;
    union_ctx->ret_flags_understood = ret_flags_understood;

    return GSS_S_COMPLETE;
}
