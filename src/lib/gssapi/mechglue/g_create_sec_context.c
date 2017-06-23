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

    if (context == NULL)
        return GSS_S_FAILURE;

    union_ctx = calloc(1, sizeof(gss_union_ctx_id_desc));
    if (union_ctx == NULL) {
        if (minor_status != NULL)
            *minor_status = ENOMEM;
        return GSS_S_UNAVAILABLE;
    }

    union_ctx->loopback = union_ctx;

    *context = (gss_ctx_id_t)union_ctx;

    if (minor_status != NULL)
        *minor_status = 0;

    return GSS_S_COMPLETE;
}
