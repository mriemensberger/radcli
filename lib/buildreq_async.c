/*
 * Copyright (C) 1995,1997 Lars Fenneberg
 * Copyright (C) 2022 Cadami GmbH info@cadami.net
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 * -----------------------------------------------------------------------------
 *
 *  Contains asynchronous versions of the functions in buildreq.c, intended for
 *  direct usage by the user.
 *
 *  Currently does not provide the proxy versions of auth() and acct().
 */

// TODO unnecessary headers?
#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include "util.h"


/* TODO:
 * In the function below, rc_type type is not documented in the original
 * rc_aaa_ctx_server() in buildreq.c. Find out what it does and document it
 * there and here.
 */

/** Builds an asynchronous authentication/accounting request for port id
 * nas_port with the value_pairs send and submits it to a server. This function
 * keeps its state in ctx after a successful operation. It can be deallocated
 * using rc_aaa_ctx_free().
 * Note that this function currently only supports sending to ONE server. Only
 * the first server in aaaserver is used.
 *
 * @param mhdl a multihandle to enqueue requests into, allocated with rc_async_prepare_multihandle()
 * @param rh a handle to parsed configuration. This configuration should always
 * contain a timeout > 0 - otherwise zombie requests might occur.
 * @param ctx if non-NULL it will contain the context of the request;
 * Its initial value should be NULL and it must be released using rc_aaa_ctx_free().
 * @param aaaserver a non-NULL SERVER to send the message to.
 * @param nas_port the physical NAS port number to use (may be zero).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @param add_nas_port this should be zero; if non-zero it will include PW_NAS_PORT in sent pairs.
 * @param request_type one of standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @return OK_RC (0) on success, negative on failure as return value.
 */
int
rc_async_aaa_ctx_server(struct rc_async_multihandle *mhdl, rc_handle *rh,
		RC_AAA_CTX **ctx, SERVER *aaaserver, rc_type type,
		uint32_t nas_port, VALUE_PAIR *send, int add_nas_port,
		rc_standard_codes request_type)
{
	SEND_DATA data;
	VALUE_PAIR *adt_vp = NULL;
	int result;
	int timeout = rc_conf_int(rh, "radius_timeout");
	int retries = rc_conf_int(rh, "radius_retries");
	double start_time = 0;
	double now = 0;
	time_t dtime;
	int servernum;

	data.send_pairs = send;
	data.receive_pairs = NULL;

	if (add_nas_port != 0 && !rc_avpair_get(data.send_pairs, PW_NAS_PORT, 0)) {
		/*
		 * Fill in NAS-Port
		 */
		if (rc_avpair_add(rh, &(data.send_pairs), PW_NAS_PORT,
				&nas_port, 0, 0) == NULL) {
			return ERROR_RC;
		}
	}

	if (request_type == PW_ACCOUNTING_REQUEST) {
		/*
		 * Fill in Acct-Delay-Time
		 */
		dtime = 0;
		now = rc_getmtime();
		adt_vp = rc_avpair_get(data.send_pairs, PW_ACCT_DELAY_TIME, 0);
		if (adt_vp == NULL) {
			adt_vp = rc_avpair_add(rh, &(data.send_pairs),
				PW_ACCT_DELAY_TIME, &dtime, 0, 0);

			if (adt_vp == NULL)
				return ERROR_RC;

			start_time = now;
		} else {
			start_time = now - adt_vp->lvalue;
		}
	}

	if (aaaserver->max > 1) {
		rc_log(LOG_WARNING, "%s: More than one target RADIUS server. "
			"async-radcli currently supports only requests to 1 server "
			"per request. Ignoring the other ones.", __func__);
	}

	servernum = 0;
	rc_buildreq(rh, &data, request_type, aaaserver->name[servernum],
		    aaaserver->port[servernum],
		    aaaserver->secret[servernum], timeout, retries);

	if (request_type == PW_ACCOUNTING_REQUEST) {
		dtime = rc_getmtime() - start_time;
		rc_avpair_assign(adt_vp, &dtime, 0);
	}

	result = rc_async_send_server_ctx(mhdl, rh, ctx, &data, type);
	if (result != OK_RC) {
		DEBUG(LOG_INFO, "rc_async_send_server_ctx returned error (%d) for server %u: (remaining: %d)",
			result, servernum, aaaserver->max-servernum);
	}

	return result;
}


/** Builds an asynchronous authentication request for port id nas_port with the value_pairs send and submits it to a server. The request is enqueued into mhdl.
 * The result can later be collected with rc_async_get_next_response().
 *
 * @param mhdl a multihandle allocated with rc_async_prepare_multihandle()
 * @param rh a handle to parsed configuration. This configuration should always
 * contain a timeout > 0 - otherwise zombie requests might occur.
 * @param nas_port the physical NAS port number to use (may be zero).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @return received value_pairs in received, messages from the server in
 *  and OK_RC (0) on success, negative on failure as return value.
 */
int
rc_async_auth(struct rc_async_multihandle *mhdl, rc_handle *rh,
		uint32_t nas_port, VALUE_PAIR *send)
{
	SERVER *aaaserver = rc_conf_srv(rh, "authserver");
	if (!aaaserver)
		return ERROR_RC;

	return rc_async_aaa_ctx_server(mhdl, rh, NULL, aaaserver, AUTH,
			nas_port, send, 1, PW_ACCESS_REQUEST);
}


/** Builds an asynchronous accounting request for port id nas_port with the value_pairs at send. The request is enqueued into mhdl.
 * The result can later be collected with rc_async_get_next_response().
 *
 * @note NAS-IP-Address, NAS-Port and Acct-Delay-Time get filled in by this function, the rest has to be supplied.
 *
 * @param mhdl a multihandle allocated with rc_async_prepare_multihandle()
 * @param rh a handle to parsed configuration. This configuration should always
 * contain a timeout > 0 - otherwise zombie requests might occur.
 * @param nas_port the physical NAS port number to use (may be zero).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @return OK_RC (0) on success, negative on failure as return value.
 */
int
rc_async_acct(struct rc_async_multihandle *mhdl, rc_handle *rh,
		uint32_t nas_port, VALUE_PAIR *send)
{
	SERVER *aaaserver = rc_conf_srv(rh, "acctserver");
	if (!aaaserver)
		return ERROR_RC;

	return rc_async_aaa_ctx_server(mhdl, rh, NULL, aaaserver, ACCT,
			nas_port, NULL, 1, PW_ACCOUNTING_REQUEST);
}
