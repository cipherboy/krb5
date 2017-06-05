/* #pragma ident	                                                         */

/*
 *  glue routine for gss_accept_sec_context
 */

#include "mglueP.h"
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>
#include <time.h>

#ifndef LEAN_CLIENT


OM_uint32 KRB5_CALLCONV
gss_create_sec_context (minor_status,
                        context)

OM_uint32    *minor_status;
gss_ctx_id_t *context;
{
    OM_uint32 status_out = GSS_S_FAILURE;
    gss_OID selected_mech_type = GSS_C_NO_OID;
    gss_mechanism mech = NULL;

    if (minor_status != NULL)
        *minor_status = 0;


    status_out = gssint_select_mech_type(minor_status, GSS_C_NO_OID, &selected_mech_type);

    if (status_out != GSS_S_COMPLETE)
        return status_out;

    mech = gssint_get_mechanism(selected_mech_type);

    if (mech == NULL)
        return GSS_S_BAD_MECH;

    if (mech->gss_create_sec_context == NULL)
        return GSS_S_UNAVAILABLE;

    return mech->gss_create_sec_context(minor_status, context);
}

#endif
