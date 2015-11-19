#ifndef _GSM_USSD_MAP_H
#define _GSM_USSD_MAP_H

#include <openbsc/gprs_gsup_client.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_ussd_map_proto.h>

int ussd_map_read_cb(struct gprs_gsup_client *sup_client,
		     struct msgb *msg);

int ussd_map_tx_message(struct gsm_network *net, struct ss_request *req,
			const char *extension, uint32_t ref);

#endif /* _GSM_USSD_MAP_H */
