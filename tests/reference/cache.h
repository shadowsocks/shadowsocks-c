/*
 * cache.h - Define the cache manager interface
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

/*
 * The first implementation was by Oliver Lorenz (ol), olli@olorenz.org,
 * https://olorenz.org, originally on top of uthash; now a fixed slab.
 */

#ifndef _CACHE_
#define _CACHE_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A fixed-capacity cache of (key, data) pairs ordered by last use. All of
 * its memory is reserved by cache_create(), so inserting, looking up and
 * evicting never allocate.
 *
 * Inserting evicts the least recently used entry once the cache holds
 * `capacity` entries, so at most capacity - 1 entries remain afterwards.
 * Evicted, removed and cleared entries are handed to free_cb(key, data);
 * without a free_cb their data is released with free(). Entries whose data
 * is NULL are dropped silently. free_cb may use the cache.
 */
struct cache;

/* Default longest key: a UDP relay key (struct sockaddr_storage plus an
 * address family). */
#define CACHE_DEFAULT_MAX_KEY 160

int cache_create(struct cache **dst, const size_t capacity,
                 void (*free_cb)(void *key, void *element));
/* Like cache_create() for keys of at most max_key_len bytes (at most 255). */
int cache_create_keyed(struct cache **dst, size_t capacity, size_t max_key_len,
                       void (*free_cb)(void *key, void *element));
int cache_delete(struct cache *cache, int keep_data);
int cache_clear(struct cache *cache, double age);
int cache_lookup(struct cache *cache, char *key, size_t key_len, void *result);
int cache_insert(struct cache *cache, char *key, size_t key_len, void *data);
int cache_remove(struct cache *cache, char *key, size_t key_len);
int cache_key_exist(struct cache *cache, char *key, size_t key_len);
size_t cache_size(const struct cache *cache);

#ifdef __cplusplus
}
#endif

#endif
