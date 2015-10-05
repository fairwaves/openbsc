/* GTP Hub Implementation */

/* (C) 2015 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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
 */

#pragma once

#include <stdint.h>
#include <sys/socket.h>

#include <osmocom/core/select.h>


/* general */

enum gtphub_port_idx {
	GTPH_PORT_CONTROL = 0,
	GTPH_PORT_USER = 1,
	GTPH_PORT_N
};

extern const char* const gtphub_port_idx_names[GTPH_PORT_N];


/* Generator for unused TEI IDs. So far this counts upwards from zero, but the
 * implementation may change in the future. Treat this like an opaque struct. */
struct tei_pool {
	uint32_t last_tei;
};

void tei_pool_init(struct tei_pool *pool);

/* Return the next unused TEI from the tei_pool. */
uint32_t tei_pool_next(struct tei_pool *pool);


struct tei_mapping {
	struct llist_head entry;

	uint32_t orig;
	uint32_t repl;
};

struct tei_map {
	struct tei_pool *pool;
	struct llist_head mappings;
};

/* Initialize an (already allocated) tei_map, and set the map's TEI pool.
 * Multiple tei_map instances may use the same tei_pool. */
void tei_map_init(struct tei_map *map, struct tei_pool *pool);

/* Return a replacement TEI for tei_orig. If tei_orig is unknown, create a new
 * mapping using a so far unused TEI to map tei_orig to. Return 0 on error. */
uint32_t tei_map_get(struct tei_map *map, uint32_t tei_orig);

/* Return the original TEI for a replacement TEI. If no mapping exists to
 * tei_repl, return 0. */
uint32_t tei_map_get_rev(struct tei_map *map, uint32_t tei_repl);

/* Remove the mapping for tei_orig, if it exists. */
void tei_map_del(struct tei_map *map, uint32_t tei_orig);


/* config */

struct gtphub_cfg_addr {
	const char *addr_str;
	uint16_t port;
};

struct gtphub_cfg_bind {
	struct gtphub_cfg_addr bind;
};

struct gtphub_cfg {
	struct gtphub_cfg_bind to_sgsns[GTPH_PORT_N];
	struct gtphub_cfg_bind to_ggsns[GTPH_PORT_N];
};


/* state */

struct gtphub_addr {
	struct sockaddr_storage a;
	socklen_t l;
};

struct gtphub_peer {
	struct llist_head entry;

	struct gtphub_addr addr;
	struct tei_map teim;
};

struct gtphub_bind {
	struct osmo_fd ofd;
	struct tei_pool teip;

	/* list of struct gtphub_peer */
	struct llist_head peers;
};

struct gtphub {
	struct gtphub_bind to_sgsns[GTPH_PORT_N];
	struct gtphub_bind to_ggsns[GTPH_PORT_N];
};


/* api */

void gtphub_zero(struct gtphub *hub);
int gtphub_init(struct gtphub *hub, struct gtphub_cfg *cfg);

/* Create a new gtphub_peer instance added to peers_list.
 * Initialize to all-zero. Return a pointer to the new instance, or NULL on
 * error. */
struct gtphub_peer *gtphub_peer_new(struct gtphub_bind *bind);

/* Remove a gtphub_peer from its list and free it. */
void gtphub_peer_del(struct gtphub_peer *peer);
