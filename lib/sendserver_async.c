/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
 *
 * Copyright (C) 2022 Cadami GmbH, info@cadami.net
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 * -----------------------------------------------------------------------------
 *
 * This file contains functions to send requests to a RADIUS Server asynchronously.
 * Currently only fully supports UDP.
 * It does so by splitting the original function rc_send_server_ctx() from
 * sendserver.c into two halves:
 * 1. One for sending, which enqueues the requests into a multi handle and sends
 * 	to the server. This is currently still blocking (FIXME), but should not
 * 	be a problem, as UDP sends should not / very rarely block.
 * 2. One for receiving asynchronously.
 *
 * Note:
 * - Currently, it only fully supports UDP as the underlying protocol.
 * - (D)TLS are currently not supported
 * - TCP is not fully supported, but should work in principle. Sending the
 *   request might block, receiving the answert should be asynchronous. Use at
 *   your own risk.
 */

#include <includes.h>
#include <radcli/radcli.h>
#include <pathnames.h>
#include <poll.h>

#include <stdbool.h>

#include "sendserver_util.h"

#include "util.h"
#include "rc-md5.h"
#include "rc-hmac.h"

#if defined(HAVE_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
#endif

#if defined(__linux__)
#include <linux/in6.h>
#endif

/* This macro depends on several defines. To keep sendserver_async.h simple,
 * it's easier to redefine it here additionally to sendserver.c
 * TODO: Move it to a function in sendserver_util.c . */
#define SCLOSE(fd) if (hdl->sfuncs->close_fd) hdl->sfuncs->close_fd(fd)


struct rc_async_handle {
	int sockfd;
	AUTH_HDR *auth, *recv_auth;
	char *server_name, *p;	/* Name of server to query */
	struct sockaddr_storage our_sockaddr;
	struct addrinfo *auth_addr;
	socklen_t salen;
	int result; /* Stores to error code from try_get_server_answer() */
	int total_length;
	int length, pos;
	int retry_max;
	const rc_sockets_override *sfuncs;
	unsigned discover_local_ip;
	size_t secretlen;
	char secret[MAX_SECRET_LENGTH + 1];
	unsigned char vector[AUTH_VECTOR_LEN];
	uint8_t recv_buffer[RC_BUFFER_LEN];
	uint8_t send_buffer[RC_BUFFER_LEN];
	uint8_t *attr;
	uint16_t tlen;
	int retries;
	VALUE_PAIR *vp;
	struct pollfd pfd;
	double start_time, timeout;
	struct sockaddr_storage *ss_set;
	const char *server_type;
	char *ns;
	int ns_def_hdl;

	/* These parameters were originally passed as function parameters
	 * to rc_send_server_ctx() - as they are also necessary for receiving,
	 * we add them to the state. */
	char *msg;
	SEND_DATA *data;
	rc_type type;
	RC_AAA_CTX **ctx;
	rc_handle *rh;
};


enum rc_async_multihandle_state {
	Rc_mh_waiting_for_response,
	Rc_mh_response_ready,
};


struct rc_async_handle_list_member {
	enum rc_async_multihandle_state state;
	struct rc_async_handle *hdl;
	struct rc_async_handle_list_member *previous, *next;
};



static int
insert_asynchdl(struct rc_async_multihandle *mhdl,
		struct rc_async_handle *ahdl)
{
	struct rc_async_handle_list_member *iterator, *worker, *member;

	if (!mhdl || !ahdl)
		return -1;

	member = calloc(1, sizeof(struct rc_async_handle_list_member));
	if (!member) {
		rc_log(LOG_ERR, "%s: allocation failure.", __func__);
		return -1;
	}

	/* the list member becomes the new owner of the async_handle */
	member->hdl = ahdl;
	member->previous = NULL;
	member->next = NULL;

	/* Enqueueing always means that this handle is now waiting for answer. */
	member->state = Rc_mh_waiting_for_response;

	if (!mhdl->begin) {
		mhdl->begin = member;
		mhdl->enqueued_entries++;
		return 0;
	}

	/* Position to end of the list */
	for (iterator = mhdl->begin; iterator; iterator = iterator->next)
		worker = iterator;

	worker->next = member;
	member->previous = worker;

	mhdl->enqueued_entries++;

	return 0;
}


/* Unlinks a handle from the multihandle list, but does not deallocate it. */
static void
remove_list_member(struct rc_async_multihandle *mhdl,
		struct rc_async_handle_list_member *member)
{
	struct rc_async_handle_list_member *previous = NULL, *next = NULL;

	if (!mhdl || !member)
		return;

	previous = member->previous;
	next = member->next;

	if (previous && next) {
		previous->next = next;
		next->previous = previous;
	} else if (previous && !next) {
		previous->next = NULL;
	} else if (!previous && next) {
		mhdl->begin = next;
		next->previous = NULL;
	} else {
		mhdl->begin = NULL;
	}

	/*
	 * 'data' is freed here, because the relevant content transfered to the
	 * user is residing in VALUE_PAIR *rcvpairs, which is later free()ed in
	 * rc_async_cleanup_response().
	 * The same is the case for the server answer in char *msg.
	 */
	free(member->hdl->data);
	free(member->hdl);
	free(member);
	mhdl->enqueued_entries--;

}


static struct rc_async_handle *
rc_prepare_async_handle(void)
{
	struct rc_async_handle *ret = calloc(1, sizeof(struct rc_async_handle));

	if (!ret) {
		rc_log(LOG_ERR, "%s: Allocation failure.", __func__);
		return NULL;
	}

	/*
	 * We also have to set the default values originally defined in
	 * sendserver.c
	 */
	ret->sockfd = -1;
	ret->auth_addr = NULL;
	ret->result = 0; /* 0 is maybe not a wise choice, but follows the original
			    in sendserver.c */
	ret->ss_set = NULL;
	ret->ns = NULL;
	ret->ns_def_hdl = 0;

	return ret;
}


/** Prepares a new multihandle to enqueue async requests into.
 *
 * @return Pointer to a allocated rc_async_multihandle on success, NULL on error.
 */
struct rc_async_multihandle *
rc_async_prepare_multihandle(void)
{
	struct rc_async_multihandle *mhdl = calloc(1, sizeof(struct rc_async_multihandle));
	if (!mhdl) {
		rc_log(LOG_ERR, "%s: allocation failure.", __func__);
		return NULL;
	}

	mhdl->enqueued_entries = 0;
	mhdl->ready_entries = 0;
	mhdl->begin = NULL;

	return mhdl;
}


/** Deallocates a rc_async_multihandle and all requests enqueued into it.
 *
 * @param mhdl a multihandle containing N parallel requests.
 */
void
rc_async_free_multihandle(struct rc_async_multihandle *mhdl)
{
	struct rc_async_handle_list_member *iter;

	if (!mhdl)
		return;

	for (iter = mhdl->begin; iter; iter = iter->next) {
		remove_list_member(mhdl, iter);
	}

	free(mhdl);
}


static void
check_warn_socktype(rc_handle *rh)
{
	if (rh->so_type != RC_SOCKET_UDP) {
		rc_log(LOG_WARNING, "rc_async_send_server_ctx should only be "
			"used with pure UDP-Sockets. Sending might block!");
	}
}


/*
 * Try to set the socket to non-blocking for receiving the server's answer
 * asynchronously. Warn the user should that not work, but don't halt the program.
 */
static void
set_sock_to_nonblock(int sock)
{
	int flags = 0;

	flags = fcntl(sock, F_GETFL);
	if (flags == -1) {
		rc_log(LOG_WARNING, "%s: Could not obtain old socket flags. "
			"Overwriting old ones with O_NONBLOCK only.", __func__);
		flags = O_NONBLOCK;
	} else {
		flags |= O_NONBLOCK;
	}

	if (fcntl(sock, F_SETFL, flags) == -1) {
		rc_log(LOG_ERR, "%s: Failed to set socket to nonblocking. "
			"Future receive-attempts might block!", __func__);
	}
}


static int
check_configure_ipv6(struct rc_async_handle *hdl, rc_handle *rh)
{
	int sock_opt = 0;
	char *non_temp_addr = NULL;

	if (hdl->our_sockaddr.ss_family != AF_INET6)
		return 0;

	/* Check for IPv6 non-temporary address support */
	non_temp_addr = rc_conf_str(rh, "use-public-addr");
	if (non_temp_addr && (strcasecmp(non_temp_addr, "true") != 0))
		return 0;

#if defined(__linux__)
	sock_opt = IPV6_PREFER_SRC_PUBLIC;
	if (setsockopt(hdl->sockfd, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES,
			&sock_opt, sizeof(sock_opt)) != 0) {
		rc_log(LOG_ERR, "rc_send_async_server: setsockopt: %s",
			strerror(errno));
		return ERROR_RC;
	}

#elif defined(BSD) || defined(__APPLE__)
	sock_opt = 0;
	if (setsockopt(hdl->sockfd, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR,
			&sock_opt, sizeof(sock_opt)) != 0) {
		rc_log(LOG_ERR, "rc_send_async_server: setsockopt: %s",
			strerror(errno));
		return ERROR_RC;
	}
#else
	rc_log(LOG_INFO, "rc_send_server: Usage of non-temporary IPv6"
			" address is not supported in this system");
#endif

	return 0;
}


static SEND_DATA *
copy_data_struct(SEND_DATA *data)
{
	SEND_DATA *ret = calloc(1, sizeof(SEND_DATA));
	if (!ret) {
		rc_log(LOG_ERR, "%s: Allocation failure.", __func__);
		return NULL;
	}

	memcpy(ret, data, sizeof(SEND_DATA));

	return ret;
}


/** Sends a request to a RADIUS server and enqueues the request.
 * Note that in the current implementation, this function is only really
 * non-blocking for UDP as its transport.
 *
 * @param mhdl a multihandle containing N parallel requests
 * @param rh a handle to parsed configuration
 * @param ctx if non-NULL it will contain the context of sent request; It must be released using rc_aaa_ctx_free().
 * @param data a pointer to a SEND_DATA structure
 * @param msg must be an array of %PW_MAX_MSG_SIZE or NULL; will contain the concatenation of
 *	any %PW_REPLY_MESSAGE received.
 * @param type must be %AUTH or %ACCT
 * @return OK_RC (0) on success, negative (i.e., ERROR_RC) on failure as return
 * value. In case of failure, your request has not been enqueued into the
 * multihandle.
 */
int
rc_async_send_server_ctx(struct rc_async_multihandle *mhdl, rc_handle *rh,
		RC_AAA_CTX **ctx, SEND_DATA *data, rc_type type)
{
	int result = 0;
	struct rc_async_handle *hdl = rc_prepare_async_handle();
	if (!hdl)
		return ERROR_RC;

	if (!mhdl || !rh ) {
		result = ERROR_RC;
		goto exit;
	}

	/* Warn the user should he call this function with something other than
	 * a UDP-Socket in the rc_handle. */
	check_warn_socktype(rh);

	/* Store data and msg to the state for the receive function */

	hdl->data = copy_data_struct(data);
	if (!hdl->data) {
		result = ERROR_RC;
		goto exit;
	}

	/* Allocate a message in any case. Later returned to the user, who shall
	 * decide what to do with it. */
	hdl->msg = calloc(PW_MAX_MSG_SIZE, sizeof(char));
	if (!hdl->msg) {
		rc_log(LOG_ERR, "%s: Allocation failure.", __func__);
		result = ERROR_RC;
		goto exit;
	}

	hdl->type = type;
	hdl->ctx = ctx;
	hdl->rh = rh;
	hdl->retry_max = data->retries;	/* Max. numbers to try for reply */
	hdl->retries = 0;		/* Init retry cnt for blocking call */
	hdl->timeout = data->timeout;


	hdl->server_name = data->server;
	if (!hdl->server_name || hdl->server_name[0] == '\0')
		return ERROR_RC;

	/* Check the namespace configuration */
	hdl->ns = rc_conf_str(rh, "namespace");
	if (hdl->ns) {
		if (rc_set_netns(hdl->ns, &(hdl->ns_def_hdl)) == -1) {
			rc_log(LOG_ERR, "rc_async_send_server_ctx: "
				"namespace %s set failed", hdl->ns);
			return ERROR_RC;
		}
	}

	if ((hdl->vp = rc_avpair_get(data->send_pairs, PW_SERVICE_TYPE, 0)) &&
			(hdl->vp->lvalue == PW_ADMINISTRATIVE)) {
		strcpy(hdl->secret, MGMT_POLL_SECRET);
		hdl->auth_addr = rc_getaddrinfo(hdl->server_name,
			hdl->type == AUTH ? PW_AI_AUTH : PW_AI_ACCT);
		if (hdl->auth_addr == NULL) {
			result = ERROR_RC;
			goto exit;
		}
	} else {
		if (hdl->data->secret != NULL) {
			strlcpy(hdl->secret, hdl->data->secret, MAX_SECRET_LENGTH);
		}

		if (rc_find_server_addr(rh, hdl->server_name, &(hdl->auth_addr),
				hdl->secret, hdl->type) != 0) {
			rc_log(LOG_ERR,
			       "rc_send_server: unable to find server: %s",
			       hdl->server_name);
			result = ERROR_RC;
			goto exit;
		}
	}

	hdl->sfuncs = &rh->so;

	if (hdl->sfuncs->static_secret) {
		/* any static secret set in sfuncs overrides the configured */
		strlcpy(hdl->secret, hdl->sfuncs->static_secret,
			MAX_SECRET_LENGTH);
	}

	if (hdl->sfuncs->lock) {
		if (hdl->sfuncs->lock(hdl->sfuncs->ptr) != 0) {
			rc_log(LOG_ERR, "%s: lock error", __func__);
			result = ERROR_RC;
			goto exit;
		}
	}

	rc_own_bind_addr(rh, &(hdl->our_sockaddr));
	hdl->discover_local_ip = 0;
	if (hdl->our_sockaddr.ss_family == AF_INET) {
		if (((struct sockaddr_in *)(&(hdl->our_sockaddr)))->sin_addr.s_addr ==
				INADDR_ANY) {
			hdl->discover_local_ip = 1;
		}
	}

	DEBUG(LOG_ERR, "DEBUG: rc_send_server: creating socket to: %s",
		hdl->server_name);
	if (hdl->discover_local_ip) {
		result = rc_get_srcaddr(SA(&(hdl->our_sockaddr)), hdl->auth_addr->ai_addr);
		if (result != OK_RC) {
			memset(hdl->secret, '\0', sizeof(hdl->secret));
			rc_log(LOG_ERR,
			       "rc_send_server: cannot figure our own address");
			goto exit;
		}
	}

	if (hdl->sfuncs->get_fd) {
		hdl->sockfd = hdl->sfuncs->get_fd(hdl->sfuncs->ptr, SA(&(hdl->our_sockaddr)));
		if (hdl->sockfd < 0) {
			memset(hdl->secret, '\0', sizeof(hdl->secret));
			rc_log(LOG_ERR, "rc_send_async_server: socket: %s", strerror(errno));
			result = ERROR_RC;
			goto exit;
		}
	}

	result = check_configure_ipv6(hdl, rh);
	if (result == ERROR_RC)
		goto exit;

	if (hdl->data->svc_port) {
		if (hdl->our_sockaddr.ss_family == AF_INET) {
			((struct sockaddr_in *)hdl->auth_addr->ai_addr)->sin_port =
				htons((unsigned short)hdl->data->svc_port);
		} else {
			((struct sockaddr_in6 *)hdl->auth_addr->ai_addr)->sin6_port =
				htons((unsigned short)hdl->data->svc_port);
		}
	}

	/*
	 * Fill in NAS-IP-Address (if needed)
	 */
	if (rh->nas_addr_set) {
		rc_avpair_remove(&(hdl->data->send_pairs), PW_NAS_IP_ADDRESS, 0);
		rc_avpair_remove(&(hdl->data->send_pairs), PW_NAS_IPV6_ADDRESS, 0);

		hdl->ss_set = &rh->nas_addr;
	} else if (rc_avpair_get(hdl->data->send_pairs, PW_NAS_IP_ADDRESS, 0) == NULL &&
			rc_avpair_get(hdl->data->send_pairs, PW_NAS_IPV6_ADDRESS, 0) == NULL) {
		hdl->ss_set = &(hdl->our_sockaddr);
	}

	if (hdl->ss_set) {
		if (hdl->ss_set->ss_family == AF_INET) {
			uint32_t ip;
			ip = *((uint32_t*) (&((struct sockaddr_in *)hdl->ss_set)->sin_addr));
			ip = ntohl(ip);

			rc_avpair_add(rh, &(hdl->data->send_pairs),
					PW_NAS_IP_ADDRESS, &ip, 0, 0);
		} else {
			void *tmp_pt;
			tmp_pt = &((struct sockaddr_in6 *)hdl->ss_set)->sin6_addr;
			rc_avpair_add(rh, &(hdl->data->send_pairs),
					PW_NAS_IPV6_ADDRESS, tmp_pt, 16, 0);
		}
	}

	/*
	 * Fill in NAS-Identifier (if needed)
	 */
	hdl->p = rc_conf_str(rh, "nas-identifier");
	if (hdl->p != NULL) {
		rc_avpair_remove(&(hdl->data->send_pairs), PW_NAS_IDENTIFIER, 0);
		rc_avpair_add(rh, &(hdl->data->send_pairs),
			      PW_NAS_IDENTIFIER, hdl->p, -1, 0);
	}

	/* Build a request */
	hdl->auth = (AUTH_HDR *) hdl->send_buffer;
	hdl->auth->code = hdl->data->code;
	hdl->auth->id = hdl->data->seq_nbr;

	if (hdl->data->code == PW_ACCOUNTING_REQUEST) {
		hdl->server_type = "acct";
		hdl->total_length = rc_pack_list(hdl->data->send_pairs,
				hdl->secret, hdl->auth) + AUTH_HDR_LEN;

		hdl->tlen = htons((unsigned short)hdl->total_length);
		memcpy(&(hdl->auth->length), &(hdl->tlen), sizeof(uint16_t));

		memset((char *)hdl->auth->vector, 0, AUTH_VECTOR_LEN);
		hdl->secretlen = strlen(hdl->secret);
		memcpy((char *)hdl->auth + hdl->total_length, hdl->secret, hdl->secretlen);
		rc_md5_calc(hdl->vector, (unsigned char *)hdl->auth,
			    hdl->total_length + hdl->secretlen);
		memcpy((char *)hdl->auth->vector, (char *)hdl->vector, AUTH_VECTOR_LEN);
	} else {
		rc_random_vector(hdl->vector);
		memcpy((char *)hdl->auth->vector, (char *)hdl->vector, AUTH_VECTOR_LEN);

		hdl->total_length = rc_pack_list(hdl->data->send_pairs, hdl->secret,
			hdl->auth) + AUTH_HDR_LEN;

		hdl->auth->length = htons((unsigned short)hdl->total_length);

		/* If EAP message we MUST add a Message-Authenticator attribute */
		if (rc_avpair_get(hdl->data->send_pairs, PW_EAP_MESSAGE, 0) != NULL) {
			hdl->total_length = add_msg_auth_attr(rh, hdl->secret,
				hdl->auth, hdl->total_length);
		}
	}

	/* FIXME: this debug variable is defined at the world's end somewhere.
	 * Give it a deterministic name. */
	if (radcli_debug) {
		char our_addr_txt[50] = "";	/* hold a text IP */
		char auth_addr_txt[50] = "";	/* hold a text IP */

		getnameinfo(SA(&(hdl->our_sockaddr)), SS_LEN(&(hdl->our_sockaddr)),
			NULL, 0, our_addr_txt, sizeof(our_addr_txt),
			NI_NUMERICHOST);
		getnameinfo(hdl->auth_addr->ai_addr, hdl->auth_addr->ai_addrlen,
			NULL, 0, auth_addr_txt, sizeof(auth_addr_txt),
			NI_NUMERICHOST);

		DEBUG(LOG_ERR,
			"DEBUG: timeout=%d retries=%d local %s : 0, remote %s : %u\n",
			hdl->data->timeout, hdl->retry_max, our_addr_txt,
			auth_addr_txt, hdl->data->svc_port);
	}

	/* Here, the socket is still in blocking mode and we just write to it,
	 * trusting that it will never block, as we currently only support UDP
	 * sockets. */
	do {
		result = hdl->sfuncs->sendto(hdl->sfuncs->ptr, hdl->sockfd,
			(char *)(hdl->auth), (unsigned)(hdl->total_length), 0,
			SA(hdl->auth_addr->ai_addr), hdl->auth_addr->ai_addrlen);
	} while (result == -1 && errno == EINTR);

	if (result == -1) {
		result = errno == ENETUNREACH ? NETUNREACH_RC : ERROR_RC;
		rc_log(LOG_ERR, "%s: socket: %s", __FUNCTION__, strerror(errno));
		goto exit;
	}

	/* Store when this request has been submitted, so we can later check
	 * if the request has timed out. */
	hdl->start_time = rc_getmtime();

	/* If we reached this point, everything went OK. */
	result = OK_RC;

	/*
	 * Try to set the socket to non-blocking for the subsequent attempts to
	 * receive the server's answer.
	 * Should that not work, just warn the user / application, but do not
	 * terminate anything. Receiving blocking is still better than not
	 * receiving anything at all.
	 */
	set_sock_to_nonblock(hdl->sockfd);


exit:
	if (hdl->sfuncs->unlock)
		if (hdl->sfuncs->unlock(hdl->sfuncs->ptr) != 0)
			rc_log(LOG_ERR, "%s: unlock error", __func__);

	if (hdl->ns) {
		if (rc_reset_netns(&(hdl->ns_def_hdl)) == -1) {
			rc_log(LOG_ERR, "rc_send_async_server: namespace %s reset failed",
				hdl->ns);
			result = ERROR_RC;
		}
	}

	/* In this send function, we only free resources in case of an error,
	 * because the receive-function needs them as well. It will free them. */
	if (result != ERROR_RC) {
		/* If everything went right, enqueue the asynchandle into
		 * the multihandle. */
		int ret = insert_asynchdl(mhdl, hdl);

		if (ret != 0) {
			rc_log(LOG_ERR, "rc_async_send_server_ctx: Could not "
				"enqueue async-handle.");
			result = ERROR_RC;
		}
	}

	if (result == ERROR_RC) {
		SCLOSE(hdl->sockfd);
		if (hdl->data) free(hdl->data);
		if (hdl->msg) free(hdl->msg);
		free(hdl);

		if (hdl->auth_addr) {
			freeaddrinfo(hdl->auth_addr);
			hdl->auth_addr = NULL;
		}
	}

	return result;
}


static bool
packet_is_valid(struct rc_async_handle *hdl)
{
	hdl->attr = hdl->recv_buffer + AUTH_HDR_LEN;

	while (hdl->attr < (hdl->recv_buffer + hdl->length)) {
		if (hdl->attr[0] == 0) {
			rc_log(LOG_ERR,
				"%s: recvfrom: %s:%d: attribute zero is invalid",
				__func__, hdl->server_name, hdl->data->svc_port);
			return false;
		}

		if (hdl->attr[1] < 2) {
			rc_log(LOG_ERR,
				"%s: recvfrom: %s:%d: attribute length is too small",
				__func__, hdl->server_name, hdl->data->svc_port);
			return false;
		}

		if ((hdl->attr + hdl->attr[1]) > (hdl->recv_buffer + hdl->length)) {
			rc_log(LOG_ERR,
				"%s: recvfrom: %s:%d: attribute overflows the packet",
				__func__, hdl->server_name, hdl->data->svc_port);
			return false;
		}

		hdl->attr += hdl->attr[1];
	}

	return true;
}


static int
check_server_response_code(uint8_t code)
{
	int result = BADRESP_RC;

	switch (code) {
	case PW_ACCESS_ACCEPT:
	case PW_PASSWORD_ACK:
	case PW_ACCOUNTING_RESPONSE:
		result = OK_RC;
		break;

	case PW_ACCESS_REJECT:
	case PW_PASSWORD_REJECT:
		result = REJECT_RC;
		break;

	case PW_ACCESS_CHALLENGE:
		result = CHALLENGE_RC;
		break;

	default:
		rc_log(LOG_ERR, "rc_send_server: received RADIUS server "
			"response neither ACCEPT nor REJECT, code=%d is invalid",
			code);
		result = BADRESP_RC;
		break;
	}

	return result;
}


/*
 * Checks whether the request has been pending for too long by now. The start
 * time has been set in rc_async_send_server_ctx().
 */
static void
check_for_timeout(struct rc_async_handle_list_member *member)
{
	double start_time = member->hdl->start_time;
	int timeout = member->hdl->timeout;
	double current_time = rc_getmtime();

	if (current_time < 0) {
		rc_log(LOG_ERR, "Function rc_getmtime() can not deliver current time."
			" Can not time out requests. Dead requests will remain enqueued.");
		return;
	}

	if (timeout < 0) {
		rc_log(LOG_ERR, "%s: Invalid timeout specified. "
			" Can not time out requests. Dead requests will remain enqueued.",
			__func__);
		return;
	}

	if (current_time - start_time < timeout) {
		/* No timeout has occurred yet. */
		return;
	}

	if (member->hdl->retries >= member->hdl->retry_max) {
		member->hdl->result = TIMEOUT_RC;
		member->state = Rc_mh_response_ready;
	} else {
		member->hdl->retries++;
	}
}


/*
 * Attempts to get an answer from the server. In case of wouldblock, it returns
 * without an error so that we can later try again.
 * Otherwise, the received message / socket errors are treated as in
 * sendserver.c
 * Stores the request's result in member->hdl->result.
 */
static void
try_get_server_answer(struct rc_async_handle_list_member *member)
{
	int result = -1;
	struct rc_async_handle *hdl = member->hdl;

	hdl->salen = hdl->auth_addr->ai_addrlen;
	do {
		hdl->length = hdl->sfuncs->recvfrom(hdl->sfuncs->ptr, hdl->sockfd,
				(char *)hdl->recv_buffer, (int)sizeof(hdl->recv_buffer), 0,
				SA(hdl->auth_addr->ai_addr), &hdl->salen);
	} while (hdl->length == -1 && errno == EINTR);

	if (errno == EWOULDBLOCK) {
		/* FD is not ready, yet. Update state for clarity and exit. */
		member->state = Rc_mh_waiting_for_response;
		return;
	}

	if (hdl->length <= 0) {
		rc_log(LOG_ERR, "rc_send_server: recvfrom: %s:%d: %s",
			hdl->server_name, hdl->data->svc_port, strerror(errno));
		if (hdl->length == -1 && (errno == EAGAIN || errno == EINTR)) {
			/*
			 * TODO:
			 * The original implementation in sendserver.c does
			 * implement a jump here towards resending the package
			 * and waiting for the answer.
			 * Judge whether that has to be implemented here as well.
			 */
		}

		result = ERROR_RC;
		goto cleanup;
	}

	hdl->recv_auth = (AUTH_HDR *)(hdl->recv_buffer);

	if (hdl->length < AUTH_HDR_LEN || hdl->length < ntohs(hdl->recv_auth->length)) {
		rc_log(LOG_ERR, "rc_send_server: recvfrom: %s:%d: reply is too short",
			hdl->server_name, hdl->data->svc_port);
		result = ERROR_RC;
		goto cleanup;
	}

	/*
	 * The original function in sendserver.c checked for result != BADRESPID_RC
	 * at this position, after rc_check_reply.
	 * According to the local comment, this is only relevant for TLS. As our
	 * async-version does not implement TLS (yet), we ignore that event and,
	 * consequently, the error code for now.
	 */
	rc_check_reply(hdl->recv_auth, RC_BUFFER_LEN, hdl->secret,
		hdl->vector, hdl->data->seq_nbr);

	/*
	 *      If UDP is larger than RADIUS, shorten it to RADIUS.
	 */
	if (hdl->length > ntohs(hdl->recv_auth->length))
		hdl->length = ntohs(hdl->recv_auth->length);

	/*
	 *      Verify that it's a valid RADIUS packet before doing ANYTHING with it.
	 */
	if (!packet_is_valid(hdl)) {
		result = ERROR_RC;
		goto cleanup;
	}

	hdl->length = ntohs(hdl->recv_auth->length) - AUTH_HDR_LEN;
	if (hdl->length > 0) {
		/* The memory allocated by rc_avpair_gen() will ultimately, when
		 * the user is done with the async answer, be free()ed in
		 * rc_async_cleanup_response(). */
		hdl->data->receive_pairs = rc_avpair_gen(hdl->rh, NULL,
			hdl->recv_auth->data, hdl->length, 0);
	} else {
		hdl->data->receive_pairs = NULL;
	}

	result = populate_ctx(hdl->ctx, hdl->secret, hdl->vector);
	if (result != OK_RC)
		goto cleanup;

	/* In this async implementation, there is always a message allocated. */
	hdl->msg[0] = '\0';
	hdl->pos = 0;
	hdl->vp = hdl->data->receive_pairs;
	while (hdl->vp) {
		if ((hdl->vp = rc_avpair_get(hdl->vp, PW_REPLY_MESSAGE, 0))) {
			strappend(hdl->msg, PW_MAX_MSG_SIZE, &(hdl->pos),
				hdl->vp->strvalue);
			strappend(hdl->msg, PW_MAX_MSG_SIZE, &(hdl->pos), "\n");
			hdl->vp = hdl->vp->next;
		}
	}

	result = check_server_response_code(hdl->recv_auth->code);

cleanup:
	SCLOSE(hdl->sockfd);
	memset(hdl->secret, '\0', sizeof(hdl->secret));

	if (hdl->auth_addr) {
		freeaddrinfo(hdl->auth_addr);
	}

	if (hdl->sfuncs->unlock) {
		if (hdl->sfuncs->unlock(hdl->sfuncs->ptr) != 0) {
			rc_log(LOG_ERR, "%s: unlock error", __func__);
		}
	}

	if (hdl->ns != NULL) {
		if (-1 == rc_reset_netns(&(hdl->ns_def_hdl))) {
			rc_log(LOG_ERR, "%s: namespace %s reset failed",
				__func__, hdl->ns);
			result = ERROR_RC;
		}
	}

	/* 
	 * If we reached this point, maybe everything went right or maybe a
	 * receive error occured. Both cases are treated as "response ready",
	 * because the request has now been processed.
	 * It's up to the user to evaluate what happened exactly, later. This
	 * can be done through checking the results later passed to the library's
	 * user in the struct rc_async_response.
	 */
	member->state = Rc_mh_response_ready;

	member->hdl->result = result;
}


static bool
handle_has_ready_pollfd(struct rc_async_handle *hdl,
		struct pollfd *pollfds, unsigned pollfds_len)
{
	unsigned i;

	if (!pollfds)
		return false;

	for (i = 0; i < pollfds_len; i++) {
		if (hdl->sockfd == pollfds[i].fd)
			if (pollfds[i].revents == POLLIN)
				return true;
	}

	return false;
}


/** Processes all the async handles to the next step if their pollfd demands so.
 * Checks all handles for timeouts.
 *
 * @param mhdl a multihandle containing N parallel requests.
 * @param pollfds the pollfds returned by rc_async_get_pollfds().
 * @param pollfds_len the number of entries in pollfds. 
 * @return the number of ready handles, -1 on error.
 */
int
rc_async_process(struct rc_async_multihandle *mhdl, struct pollfd *pollfds,
		unsigned pollfds_len)
{
	struct rc_async_handle_list_member *iter;

	if (!mhdl || (pollfds_len != 0 && !pollfds)) {
		rc_log(LOG_ERR, "%s: NULL-Pointer as argument.", __func__);
		return -1;
	}
	if (!(mhdl->begin) || mhdl->enqueued_entries == 0) {
		/* There are no entries to be processed. */
		return 0;
	}

	if (pollfds_len == 0) {
		/* FIXME:
		 * This should actually be supported - if no pollfds are
		 * provided, the function should iterate over all FDs and try
		 * to receive an them.
		 * Unfortunately, this sometimes causes all the FDs to always
		 * return EWOULDBLOCK.
		 * Find out why and repair it, so you can use rc_async_process()
		 * without poll().
		 */
		return 0;
	}

	/* TODO: this scales with n^2, but is preferable to try_receive()ing,
	 * invoking n syscalls. Make this more performant if necessary. */
	for (iter = mhdl->begin; iter; iter = iter->next) {
		if (iter->state == Rc_mh_response_ready)
			continue;
		/*
		 * We shall allow the user to use this function in busy-poll
		 * mode as well. If pollfds_len == 0, then we try to receive on
		 * all the handles.
		 */
		if (pollfds_len == 0 || handle_has_ready_pollfd(iter->hdl, pollfds, pollfds_len)) {
			try_get_server_answer(iter);
			if (iter->state == Rc_mh_response_ready) {
				mhdl->ready_entries++;
			}
		}

		/*
		 * Now check each handle for timeouts. Timed out handles will
		 * be marked with the Rc_mh_response_ready state and contain
		 * the TIMEOUT_RC result code. The user will get this result
		 * via rc_async_get_next_response() .
		 */
		if (iter->state == Rc_mh_waiting_for_response)
			check_for_timeout(iter);

		/* TODO:
		 * Later, when a version of this program is implemented
		 * where rc_async_process() is executable without pollfds,
		 * check_for_timeout() should cause retry_max calls into
		 * try_receive(), to check whether an answer has arrived.
		 */
	}

	return mhdl->ready_entries;
}


/** Cleans up a response struct and frees all memory referenced by it and its members.
 *
 * @param resp a pointer to a response struct.
 */
void
rc_async_cleanup_response(struct rc_async_response *resp)
{
	if (!resp)
		return;

	if (resp->msg)
		free(resp->msg);

	if (resp->rcvpairs)
		rc_avpair_free(resp->rcvpairs);

	memset(resp, 0, sizeof(struct rc_async_response));
}


/** Fills the passed struct with the next ready answer, if any.
 *  Note that the response struct will contain references to memory allocated on
 *  the heap by radcli. You need to free it with rc_async_cleanup_response() after
 *  you evaluated (or copied) the response's contents.
 *
 * @param mhdl a multihandle containing N parallel requests.
 * @param resp a pointer to a structure to fill the response into.
 * @return 0 on success, -1 on error, -2 if no answer was ready.
 */
int
rc_async_get_next_response(struct rc_async_multihandle *mhdl,
		struct rc_async_response *resp)
{
	bool at_least_one_ready = false;
	struct rc_async_handle_list_member *iter;

	if (!mhdl || !resp) {
		rc_log(LOG_ERR, "%s: NULL-Pointer as argument.", __func__);
		return -1;
	}

	for (iter = mhdl->begin; iter; iter = iter->next) {
		if (iter->state == Rc_mh_response_ready) {
			at_least_one_ready = true;
			break;
		}
	}

	if (!at_least_one_ready)
		return -2;

	resp->result = iter->hdl->result;
	resp->msg = iter->hdl->msg;
	resp->rcvpairs = iter->hdl->data->receive_pairs;
	resp->ctx = iter->hdl->ctx;
	resp->sockfd = iter->hdl->sockfd;

	remove_list_member(mhdl, iter);
	mhdl->ready_entries--;

	return 0;
}


/** Passes all the enqueued pollfds to the caller. Also sets the poll-flags.
 * If the user passes less space than necessary, only pollfds_len entries are
 * provided and a warning is logged.
 *
 * @param mhdl a multihandle containing N parallel requests
 * @param pollfds the pollfds returned by rc_async_get_pollfds().
 * @param pollfds_len the number of entries in pollfds.
 * @return the number of provided entries on success, -1 on error.
 */
int
rc_async_get_pollfds(struct rc_async_multihandle *mhdl, struct pollfd *pollfds,
		unsigned pollfds_len)
{
	unsigned i = 0;
	struct pollfd *fd;
	struct rc_async_handle_list_member *iter;

	if (!mhdl || !pollfds)
		return -1;

	if (pollfds_len < mhdl->enqueued_entries) {
		rc_log(LOG_WARNING, "%s: Not enough space to store all handles.",
			__func__);
	}

	for (i = 0, iter = mhdl->begin; iter && i < pollfds_len; iter = iter->next, i++) {
		fd = &pollfds[i];

		fd->fd = iter->hdl->sockfd;
		fd->revents = 0;
		fd->events = POLLIN;
	}

	return i;
}
