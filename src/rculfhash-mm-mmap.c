/*
 * rculfhash-mm-mmap.c
 *
 * mmap/reservation based memory management for Lock-Free RCU Hash Table
 *
 * Copyright 2011 - Lai Jiangshan <laijs@cn.fujitsu.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <unistd.h>
#include <sys/mman.h>
#include "rculfhash-internal.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS		MAP_ANON
#endif

#ifdef __CYGWIN__
/*
 * On cygwin, overlapping memory mappings are not allowed. However, it's
 * possible to use the MAP_NORESERVE flag which won't allocate memory for a
 * protected mapping and then use mprotect() on chunks of this mapping to
 * change the protection and allocate/deallocate the memory.
 */

/* reserve inaccessible memory space without allocation any memory */
static void *memory_map(size_t length)
{
	void *ret = mmap(NULL, length, PROT_NONE,
			MAP_NORESERVE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	assert(ret != MAP_FAILED);
	return ret;
}

/* Set protection to read/write which allocated memory */
static void memory_populate(void *ptr, size_t length)
{
	int ret __attribute__((unused));

	ret = mprotect(ptr, length, PROT_READ | PROT_WRITE);

	assert(!ret);
}

/* Set protection to none which reclaims memory */
static void memory_discard(void *ptr, size_t length)
{
	int ret __attribute__((unused));

	ret = mprotect(ptr, length, PROT_NONE);

	assert(!ret);
}
#else /* __CYGWIN__ */
/* reserve inaccessible memory space without allocation any memory */
static void *memory_map(size_t length)
{
	void *ret = mmap(NULL, length, PROT_NONE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	assert(ret != MAP_FAILED);
	return ret;
}

static void memory_populate(void *ptr, size_t length)
{
	void *ret __attribute__((unused));

	ret = mmap(ptr, length, PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	assert(ret == ptr);
}

/*
 * Discard garbage memory and avoid system save it when try to swap it out.
 * Make it still reserved, inaccessible.
 */
static void memory_discard(void *ptr, size_t length)
{
	void *ret __attribute__((unused));

	ret = mmap(ptr, length, PROT_NONE,
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	assert(ret == ptr);
}
#endif /* __CYGWIN__ */

static void memory_unmap(void *ptr, size_t length)
{
	int ret __attribute__((unused));

	ret = munmap(ptr, length);

	assert(ret == 0);
}

static
void cds_lfht_alloc_bucket_table(struct cds_lfht *ht, unsigned long order)
{
	if (order == 0) {
		if (ht->min_nr_alloc_buckets == ht->max_nr_buckets) {
			/* small table */
			ht->tbl_mmap = calloc(ht->max_nr_buckets,
					sizeof(*ht->tbl_mmap));
			assert(ht->tbl_mmap);
			return;
		}
		/* large table */
		ht->tbl_mmap = memory_map(ht->max_nr_buckets
			* sizeof(*ht->tbl_mmap));
		memory_populate(ht->tbl_mmap,
			ht->min_nr_alloc_buckets * sizeof(*ht->tbl_mmap));
	} else if (order > ht->min_alloc_buckets_order) {
		/* large table */
		unsigned long len = 1UL << (order - 1);

		assert(ht->min_nr_alloc_buckets < ht->max_nr_buckets);
		memory_populate(ht->tbl_mmap + len,
				len * sizeof(*ht->tbl_mmap));
	}
	/* Nothing to do for 0 < order && order <= ht->min_alloc_buckets_order */
}

/*
 * cds_lfht_free_bucket_table() should be called with decreasing order.
 * When cds_lfht_free_bucket_table(0) is called, it means the whole
 * lfht is destroyed.
 */
static
void cds_lfht_free_bucket_table(struct cds_lfht *ht, unsigned long order)
{
	if (order == 0) {
		if (ht->min_nr_alloc_buckets == ht->max_nr_buckets) {
			/* small table */
			poison_free(ht->tbl_mmap);
			return;
		}
		/* large table */
		memory_unmap(ht->tbl_mmap,
			ht->max_nr_buckets * sizeof(*ht->tbl_mmap));
	} else if (order > ht->min_alloc_buckets_order) {
		/* large table */
		unsigned long len = 1UL << (order - 1);

		assert(ht->min_nr_alloc_buckets < ht->max_nr_buckets);
		memory_discard(ht->tbl_mmap + len, len * sizeof(*ht->tbl_mmap));
	}
	/* Nothing to do for 0 < order && order <= ht->min_alloc_buckets_order */
}

static
struct cds_lfht_node *bucket_at(struct cds_lfht *ht, unsigned long index)
{
	return &ht->tbl_mmap[index];
}

static
struct cds_lfht *alloc_cds_lfht(unsigned long min_nr_alloc_buckets,
		unsigned long max_nr_buckets)
{
	unsigned long page_bucket_size;

	page_bucket_size = getpagesize() / sizeof(struct cds_lfht_node);
	if (max_nr_buckets <= page_bucket_size) {
		/* small table */
		min_nr_alloc_buckets = max_nr_buckets;
	} else {
		/* large table */
		min_nr_alloc_buckets = max(min_nr_alloc_buckets,
					page_bucket_size);
	}

	return __default_alloc_cds_lfht(
			&cds_lfht_mm_mmap, sizeof(struct cds_lfht),
			min_nr_alloc_buckets, max_nr_buckets);
}

const struct cds_lfht_mm_type cds_lfht_mm_mmap = {
	.alloc_cds_lfht = alloc_cds_lfht,
	.alloc_bucket_table = cds_lfht_alloc_bucket_table,
	.free_bucket_table = cds_lfht_free_bucket_table,
	.bucket_at = bucket_at,
};
