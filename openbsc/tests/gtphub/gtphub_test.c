/* Test the GTP hub */

/* (C) 2015 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmcom.de>
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

#include <stdio.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>

#include <openbsc/debug.h>

#include <openbsc/gtphub.h>

void *osmo_gtphub_ctx;

/* TODO copied from libosmo-abis/src/subchan_demux.c, remove dup */
static int llist_len(struct llist_head *head)
{
	struct llist_head *entry;
	int i = 0;

	llist_for_each(entry, head)
		i++;

	return i;
}

static void test_tei_map(void)
{
	/* Basic */
	struct tei_pool _pool;
	struct tei_pool *pool = &_pool;
	struct tei_map _map;
	struct tei_map *map = &_map;

	tei_pool_init(pool);
	tei_map_init(map, pool);

	OSMO_ASSERT(llist_empty(&map->mappings));

#define TEST_N 100
#define TEST_I 123
	uint32_t i, check_i;
	uint32_t m[TEST_N];

	/* create TEST_N mappings */
	for (i = 0; i < TEST_N; i++) {
		m[i] = tei_map_get(map, TEST_I + i);
		OSMO_ASSERT(m[i] != 0);
		OSMO_ASSERT(llist_len(&map->mappings) == (i+1));
		for (check_i = 0; check_i < i; check_i++)
			OSMO_ASSERT(m[check_i] != m[i]);
	}
	OSMO_ASSERT(llist_len(&map->mappings) == TEST_N);

	/* verify mappings */
	for (i = 0; i < TEST_N; i++) {
		OSMO_ASSERT(tei_map_get(map, TEST_I + i) == m[i]);
		OSMO_ASSERT(tei_map_get_rev(map, m[i]) == (TEST_I + i));
	}
	OSMO_ASSERT(llist_len(&map->mappings) == TEST_N);

	/* remove all mappings */
	for (i = 0; i < TEST_N; i++) {
		tei_map_del(map, TEST_I + i);
		OSMO_ASSERT(llist_len(&map->mappings) == (TEST_N - (i+1)));
	}
	OSMO_ASSERT(llist_empty(&map->mappings));
#undef TEST_N
#undef TEST_I
}

static struct log_info_cat gtphub_categories[] = {
	[DGTPHUB] = {
		.name = "DGTPHUB",
		.description = "GTP Hub",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

static struct log_info info = {
	.cat = gtphub_categories,
	.num_cat = ARRAY_SIZE(gtphub_categories),
};

int main(int argc, char **argv)
{
	osmo_init_logging(&info);
	osmo_gtphub_ctx = talloc_named_const(NULL, 0, "osmo_gtphub");

	test_tei_map();
	printf("Done\n");

	talloc_report_full(osmo_gtphub_ctx, stderr);
	return 0;
}

