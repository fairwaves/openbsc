/* Network-specific handling of mobile-originated USSDs. */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Mike Haben <michael.haben@btinternet.com>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* This module defines the network-specific handling of mobile-originated
   USSD messages. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/gsm_04_80.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/ussd.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsm0480.h>

/* Declarations of USSD strings to be recognised */
const char USSD_TEXT_OWN_NUMBER[] = "*#100#";

/* Forward declarations of network-specific handler functions */
static int send_own_number(struct gsm_subscriber_connection *conn,
			   const struct ss_header *reqhdr,
			   const struct ss_request *req);


/* Entrypoint - handler function common to all mobile-originated USSDs */
int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int rc;
	struct ss_header reqhdr;
	struct ss_request req;
	char request_string[MAX_LEN_USSD_STRING + 1];
	struct gsm48_hdr *gh;

	memset(&req, 0, sizeof(req));
	memset(&reqhdr, 0, sizeof(reqhdr));
	gh = msgb_l3(msg);
	rc = gsm0480_decode_ss_request(gh, msgb_l3len(msg), &reqhdr);
	if (!rc) {
		DEBUGP(DSS, "Incorrect SS header\n");
		msc_release_connection(conn);
		return rc;
	}

	rc = gsm0480_parse_ss_facility(gh->data + reqhdr.component_offset,
				       reqhdr.component_length,
				       &req);
	if (!rc) {
		DEBUGP(DSS, "Unhandled SS\n");
		/* TODO req.invoke_id may not be set!!! */
		rc = gsm0480_send_ussd_reject(conn, req.invoke_id, reqhdr.transaction_id);
		msc_release_connection(conn);
		return rc;
	}

	if (reqhdr.message_type == GSM0480_MTYPE_RELEASE_COMPLETE)
		return 0;

	if (reqhdr.message_type != GSM0480_MTYPE_REGISTER ||
			req.component_type != GSM0480_CTYPE_INVOKE ||
			req.opcode != GSM0480_OP_CODE_PROCESS_USS_REQ ||
			req.ussd_text_language != 0x0f)
	{
		DEBUGP(DSS, "Unexpected SS\n");
		rc = gsm0480_send_ussd_reject(conn, req.invoke_id, reqhdr.transaction_id);
		msc_release_connection(conn);
		return rc;
	}

	gsm_7bit_decode_n_ussd(request_string, MAX_LEN_USSD_STRING, req.ussd_text, req.ussd_text_len);

	if (!strcmp(USSD_TEXT_OWN_NUMBER, (const char *)request_string)) {
		DEBUGP(DSS, "USSD: Own number requested\n");
		rc = send_own_number(conn, &reqhdr, &req);
	} else {
		DEBUGP(DSS, "Unhandled USSD %s\n", request_string);
		rc = gsm0480_send_ussd_reject(conn, req.invoke_id, reqhdr.transaction_id);
	}

	/* check if we can release it */
	msc_release_connection(conn);
	return rc;
}

/* A network-specific handler function */
static int send_own_number(struct gsm_subscriber_connection *conn,
			   const struct ss_header *reqhdr,
			   const struct ss_request *req)
{
	struct ss_request rss;
	struct ss_header rssh;

	char *own_number = conn->subscr->extension;
	char response_string[GSM_EXTENSION_LENGTH + 20];
	int response_len;

	/* Need trailing CR as EOT character */
	snprintf(response_string, sizeof(response_string), "Your extension is %s\r", own_number);

	memset(&rss, 0, sizeof(rss));
	gsm_7bit_encode_n_ussd(rss.ussd_text, MAX_LEN_USSD_STRING, response_string, &response_len);
	rss.ussd_text_len = response_len;
	rss.ussd_text_language = 0x0f;

	rss.component_type = GSM0480_CTYPE_RETURN_RESULT;
	rss.invoke_id = req->invoke_id;
	rss.opcode = GSM0480_OP_CODE_PROCESS_USS_REQ;

	rssh.message_type = GSM0480_MTYPE_RELEASE_COMPLETE;
	rssh.transaction_id = reqhdr->transaction_id;

	return gsm0480_send_component(conn,
				      gsm0480_compose_ussd_component(&rss),
				      &rssh);
}
