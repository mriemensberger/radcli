/*
 * Copyright (C) 2022 Cadami GmbH info@cadami.net
 *
 * radembedded.c - a sample c program showing how to embed the configuration of a radius
 * client, using the FreeRADIUS Client Library without an external configuration file.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <syslog.h>
#include <radcli/radcli.h>
#include <string.h>

#include <poll.h>

#define AUTH_PORT_PASSWORD ":1812:testing123"
#define ACCT_PORT_PASSWORD ":1813:testing123"
#define SERVER_ADDR "localhost"

#define NR_OF_REQS 10

int
main (int argc, char **argv)
{
	int i = 0;
	int		ret = 0;
	rc_handle 	*rh = NULL;
	uint32_t 	client_port = 0;
	uint32_t	status_type = PW_STATUS_STOP;
        VALUE_PAIR      *send = NULL;

/*
	VALUE_PAIR 	*vp = NULL;
	DICT_VALUE 	*dval = NULL;
*/
	char		username[255] = "bob@somedomain.here";
	char		callfrom[255] = "8475551212";
	char		callto[255] = "8479630116";
	char		myuuid[255] = "981743-asdf-90834klj234";
	char		auth_server_ip[255] = {0};
	char		acct_server_ip[255] = {0};
	char		*server_ip = NULL;

	if (argc > 2) {
		printf("ERROR: Invalid number of arguments.\n");
		exit(EXIT_FAILURE);
	}

	if (argc == 2)
		server_ip = argv[1];
	else
		server_ip = NULL;

/* ======================== Prepare New Request ============================= */

	/* Initialize the 'rh' structure */
	rh = rc_new();
	if (!rh) {
		printf("ERROR: Failed to allocate initial structure\n");
		exit(EXIT_FAILURE);
	}

	/* Initialize the config structure */
	rh = rc_config_init(rh);
	if (!rh) {
		printf("ERROR: Failed to initialze configuration\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Set the required options for configuration
	 */
	if (rc_add_config(rh, "dictionary", "../etc/dictionary", "config", 0) != 0) {
		printf("ERROR: Unable to set dictionary.\n");
		rc_destroy(rh);
		exit(EXIT_FAILURE);
	}

	if (rc_add_config(rh, "radius_retries", "3", "config", 0) != 0) {
		printf("ERROR: Unable to set radius_retries.\n");
		rc_destroy(rh);
		exit(EXIT_FAILURE);
	}

	if (rc_add_config(rh, "radius_timeout", "4", "config", 0) != 0) {
		printf("ERROR: Unable to set radius_timeout.\n");
		rc_destroy(rh);
		exit(EXIT_FAILURE);
	}

	/* auth/acct servers are added in the form: host[:port[:secret]]
	 * If you don't set the secret via the add_config option, you must set a 'servers'
	 * entry to specify the location of the 'servers' file which stores the secrets to
	 * be used.
	 */
	/* If the IP Address is provided via Command-line, take it for processing. Else,
	 * use localhost as default.
	 */
	if(server_ip == NULL)
		server_ip = SERVER_ADDR;

	snprintf(auth_server_ip, sizeof(auth_server_ip), "%s%s", server_ip,
		 AUTH_PORT_PASSWORD);
	snprintf(acct_server_ip, sizeof(acct_server_ip), "%s%s", server_ip,
		 ACCT_PORT_PASSWORD);

	if (rc_add_config(rh, "authserver", auth_server_ip, "config", 0) != 0) {
		printf("ERROR: Unable to set authserver.\n");
		rc_destroy(rh);
		exit(EXIT_FAILURE);
	}

	if (rc_add_config(rh, "acctserver", acct_server_ip, "config", 0) != 0) {
		printf("ERROR: Unable to set acctserver.\n");
		rc_destroy(rh);
		exit(EXIT_FAILURE);
	}

	/* Done setting configuration items */

	/* Read in the dictionary file(s) */

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) {
		printf("ERROR: Failed to initialize radius dictionary\n");
		exit(EXIT_FAILURE);
	}
	if (rc_avpair_add(rh, &send, PW_ACCT_STATUS_TYPE, &status_type, -1, 0) == NULL) {
		printf("ERROR: Failed adding Acct-Status-Type: to %d\n", status_type);
		exit(EXIT_FAILURE);
	}
	if (rc_avpair_add(rh, &send, PW_ACCT_SESSION_ID, myuuid, -1, 0) == NULL) {
		printf("ERROR: Failed adding Acct-Session-ID: to %s\n", myuuid);
		exit(EXIT_FAILURE);
	}
	if (rc_avpair_add(rh, &send, PW_USER_NAME, username, -1, 0) == NULL) {
		printf("ERROR: Failed adding User-Name: to %s\n", username);
		exit(EXIT_FAILURE);
	}
	if (rc_avpair_add(rh, &send, PW_CALLED_STATION_ID, callto, -1, 0) == NULL) {
		printf("ERROR: Failed adding Called-Station-ID: to %s\n", callto);
		exit(EXIT_FAILURE);
	}
	if (rc_avpair_add(rh, &send, PW_CALLING_STATION_ID, callfrom, -1, 0) == NULL) {
		printf("ERROR: Failed adding Calling-Station-ID: to %s\n", callfrom);
		exit(EXIT_FAILURE);
	}
	/* Initialize socket related info in RADIUS Handle */
	if (rc_apply_config(rh) == -1) {
		printf("ERROR: Failed to update Radius handle socket info");
		exit(EXIT_FAILURE);
	}


/* ====================== Sending Asynchronous Requests ===================== */

	/*
	 * Initialize a new multihandle. Each request will later be enqueued into
	 * this handle. It is the central component for async-radcli.
	 */
	struct rc_async_multihandle *mhdl = rc_async_prepare_multihandle();
	if (!mhdl) {
		puts("Could not initialize async-multihandle.");
		exit(EXIT_FAILURE);
	}

	/* Send the same request NR_OF_REQS times */
	for (i = 0; i < NR_OF_REQS; i++) {
		if(rc_async_acct(mhdl, rh, client_port, send) == OK_RC) {
			printf("Acct request %i successfully transmitted asynchronously.\n", i);
			ret = 0;
		} else {
			printf("INFO: Sending accounting request %i asynchronously failed."
				" Terminating.\n", i);
			exit(EXIT_FAILURE);
		}
	}


	unsigned received_responses = 0;
	int nr_of_poll_fds = 0;
	struct pollfd polli[NR_OF_REQS]; /* User provided pollfds, will be filled
					    by radcli. Could also be located on
					    the heap, of course. */
	struct rc_async_response response; /* A struct containing the server's
					    response to a specific request. */
	memset(&response, 0, sizeof(struct rc_async_response));

	for (;;) {
		/* Get all the currently enqueued pollable file descriptors. */
		nr_of_poll_fds = rc_async_get_pollfds(mhdl, polli, NR_OF_REQS);
		if (nr_of_poll_fds == 0) {
			puts("No more FDs to poll on.");
			break;
		} else if (nr_of_poll_fds < 0) {
			puts("Could not get pollfds.");
			exit(EXIT_FAILURE);
		}

		puts("polling");
		/* 
		 * Above, we specified a timeout of 5 seconds. After poll
		 * returns, rc_async_process() will check if any requests have
		 * timed out yet. After the timeout has occurred, the process
		 * function will try to receive for retries more times. After
		 * the last retry was unsuccessful, such requests will be
		 * marked as ready and will be returned below by
		 * rc_async_get_next_response(). The response struct's result
		 * code will contain TIMEOUT_RC for the timed out requests.
		 */
		poll(polli, nr_of_poll_fds, 1000);
		puts("poll returned");

		/* Processes all request-handles with a corresponding
		 * poll-event indicating readability. Checks all handles for
		 * timeouts. */
		rc_async_process(mhdl, polli, nr_of_poll_fds);

		do {
			ret = rc_async_get_next_response(mhdl, &response);
			if (ret == 0) {
				printf("Answer %i successfully received.\n",
					received_responses++);
			}
			/*
			 * If ret was 0, struct 'response' (as defined in
			 * radcli.h) now contains the request's status code
			 * (identical to the one the synchronous functions would
			 * return) and server's response message.
			 */

			/* 
			 * >>> Evaluate server response (response's members) here <<<
			 */

			/* 
			 * The response contains references to memory previously
			 * allocated internally by radcli.
			 * After doing stuff with the response, it has to be
			 * freed, consequently.
			 */
			rc_async_cleanup_response(&response);
		} while (ret == 0);

		if (ret == -2)
			puts("No response was ready.");
		else if (ret == -1)
			puts("Error receiving response.");
	}

	printf("%u of %u async-requests have been responded or timed out.\n",
		received_responses, NR_OF_REQS);


	/* Deallocates the multihandle and request-handles possibly still
	 * remaining within it. */
	rc_async_free_multihandle(mhdl);

	rc_destroy(rh);
	rc_avpair_free(send);

	exit(received_responses == NR_OF_REQS ? EXIT_SUCCESS : EXIT_FAILURE);
}
