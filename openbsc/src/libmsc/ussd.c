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
#include <openbsc/gsm_ussd_map.h>
#include <openbsc/ussd.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <openbsc/transaction.h>

/* Counter of open sessions */
static unsigned s_ussd_open_sessions = 0;

/* Last uniq generated session id */
static uint32_t s_uniq_ussd_sessiod_id = 0;

/* Forward declaration of USSD handler for USSD MAP interface */
static int handle_rcv_ussd_sup(struct gsm_subscriber_connection *conn, struct msgb *msg);

/* Declarations of USSD strings to be recognised */
const char USSD_TEXT_OWN_NUMBER[] = "*#100#";

/* Forward declarations of network-specific handler functions */
static int send_own_number(struct gsm_subscriber_connection *conn, const struct ss_request *req);


/* Entrypoint - handler function common to all mobile-originated USSDs */
int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int rc;
	struct ss_request req;
	char request_string[MAX_LEN_USSD_STRING + 1];
	struct gsm48_hdr *gh;

	if (conn->subscr->group->net->ussd_sup_client)
		return handle_rcv_ussd_sup(conn, msg);

	memset(&req, 0, sizeof(req));
	gh = msgb_l3(msg);
	rc = gsm0480_decode_ss_request(gh, msgb_l3len(msg), &req);
	if (!rc) {
		DEBUGP(DSS, "Unhandled SS\n");
		rc = gsm0480_send_ussd_reject(conn, &req);
		msc_release_connection(conn);
		return rc;
	}

	if (req.message_type == GSM0480_MTYPE_RELEASE_COMPLETE)
		return 0;

	if (req.message_type != GSM0480_MTYPE_REGISTER ||
			req.component_type != GSM0480_CTYPE_INVOKE ||
			req.opcode != GSM0480_OP_CODE_PROCESS_USS_REQ ||
			req.ussd_text_language != 0x0f)
	{
		DEBUGP(DSS, "Unexpected SS\n");
		rc = gsm0480_send_ussd_reject(conn, &req);
		msc_release_connection(conn);
		return rc;
	}

	gsm_7bit_decode_n_ussd(request_string, MAX_LEN_USSD_STRING, req.ussd_text, req.ussd_text_len);

	if (!strcmp(USSD_TEXT_OWN_NUMBER, (const char *)request_string)) {
		DEBUGP(DSS, "USSD: Own number requested\n");
		rc = send_own_number(conn, &req);
	} else {
		DEBUGP(DSS, "Unhandled USSD %s\n", request_string);
		rc = gsm0480_send_ussd_reject(conn, &req);
	}

	/* check if we can release it */
	msc_release_connection(conn);
	return rc;
}

/* A network-specific handler function */
static int send_own_number(struct gsm_subscriber_connection *conn, const struct ss_request *req)
{
	char *own_number = conn->subscr->extension;
	char response_string[GSM_EXTENSION_LENGTH + 20];

	/* Need trailing CR as EOT character */
	snprintf(response_string, sizeof(response_string), "Your extension is %s\r", own_number);
	return gsm0480_send_ussd_response(conn, response_string, req);
}


static int ussd_sup_send_reject(struct gsm_network *conn,
				uint32_t ref, uint8_t invokeid, uint8_t opcode)
{
	struct ss_request rej;
	rej.message_type = GSM0480_MTYPE_RELEASE_COMPLETE;
	rej.component_type = GSM0480_CTYPE_REJECT;
	rej.invoke_id = invokeid;
	rej.opcode = opcode;
	rej.ussd_text_len = 0;

	return ussd_map_tx_message(conn, &rej, NULL, ref);
}

/* Callback from USSD MAP interface */
int on_ussd_response(struct gsm_network *net, uint32_t ref, struct ss_request *req, const char *extention)
{
	struct gsm_trans *trans = trans_find_by_callref(net, ref);
	int rc = 0;

	switch (req->message_type) {
	case GSM0480_MTYPE_REGISTER:
		DEBUGP(DSS, "Network originated USSD messages isn't supported yet!\n");

		ussd_sup_send_reject(net, ref, req->invoke_id, req->opcode);
		return 0;

	case GSM0480_MTYPE_FACILITY:
	case GSM0480_MTYPE_RELEASE_COMPLETE:
		if (!trans) {
			DEBUGP(DSS, "No session was found for ref: %d!\n",
			       ref);

			ussd_sup_send_reject(net, ref, req->invoke_id, req->opcode);
			return 0;
		}
		break;
	default:
		DEBUGP(DSS, "Unknown message type 0x%02x\n", req->message_type);
		ussd_sup_send_reject(net, ref, req->invoke_id, req->opcode);
		return 0;
	}

	req->invoke_id = trans->ss.invoke_id;
	req->transaction_id = (trans->transaction_id << 4) ^ 0x80;

	if (req->component_type != GSM0480_CTYPE_REJECT) {
		rc = gsm0480_send_ussd(trans->conn, req);
	} else {
		rc = gsm0480_send_ussd_reject(trans->conn, req);
	}

	if (req->message_type == GSM0480_MTYPE_RELEASE_COMPLETE) {
		struct gsm_subscriber_connection* conn = trans->conn;

		trans_free(trans);
		msc_release_connection(conn);
	}

	return rc;
}

/* Handler function common to all mobile-originated USSDs in case if USSD MAP enabled  */
static int handle_rcv_ussd_sup(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int rc = 0;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct ss_request req;
	struct gsm_trans *trans = NULL;
	uint8_t transaction_id = ((gh->proto_discr >> 4) ^ 0x8); /* flip */

	if (!conn->subscr)
		return -EIO;

	memset(&req, 0, sizeof(req));

	DEBUGP(DSS, "handle ussd tid=%d: %s\n", transaction_id, msgb_hexdump(msg));
	trans = trans_find_by_id(conn, GSM48_PDISC_NC_SS, transaction_id);

	rc = gsm0480_decode_ss_request(gh, msgb_l3len(msg), &req);
	if (!rc) {
		DEBUGP(DSS, "Unhandled SS\n");
		if (!trans) {
			goto transaction_not_found;
		}

		/* don't know how to process */
		goto failed_transaction;
	}

	switch (req.message_type) {
	case GSM0480_MTYPE_REGISTER:
		if (trans) {
			/* we already have a transaction, ignore this message */
			goto release_conn;
		}

		trans = trans_alloc(conn->bts->network, conn->subscr,
				    GSM48_PDISC_NC_SS,
				    transaction_id, s_uniq_ussd_sessiod_id++);
		if (!trans) {
			DEBUGP(DSS, "Failed to create new ussd transaction\n");
			goto transaction_not_found;
		}

		trans->conn = conn;
		trans->ss.invoke_id = req.invoke_id;
		trans->ss.mo = 1;
		trans->ss.dirty = 1;
		break;

	case GSM0480_MTYPE_FACILITY:
		if (!trans) {
			DEBUGP(DSS, "no session found invoke_id=%d tid=%d\n",
			       req.invoke_id, transaction_id);
			goto transaction_not_found;
		}
		break;

	case GSM0480_MTYPE_RELEASE_COMPLETE:
		if (!trans) {
			DEBUGP(DSS, "RELEASE_COMPLETE to non-existing transaction!\n");
			goto release_conn;
		}

		trans_free(trans);
		goto release_conn;
	}

	rc = ussd_map_tx_message(conn->subscr->group->net, &req,
				 conn->subscr->extension, trans->callref);
	if (rc) {
		/* do not send reject if we failed with the message */
		trans->ss.dirty = 0;

		DEBUGP(DSS, "Unable tp send uss over sup reason: %d\n", rc);
		goto failed_transaction;
	}
	return 0;

failed_transaction:
	trans_free(trans);

transaction_not_found:
	gsm0480_send_ussd_reject(conn, &req);

release_conn:
	msc_release_connection(conn);
	return rc;
}

void _ussd_trans_free(struct gsm_trans *trans)
{
	if (trans->ss.dirty) {
		trans->ss.dirty = 0;

		ussd_sup_send_reject(trans->net, trans->callref, trans->ss.invoke_id, 0);
	}
}

