/*
 * Borg cache synchronizer,
 * based on a MessagePack for Python unpacking routine
 *
 * Copyright (C) 2009 Naoki INADA
 * Copyright (c) 2017 Marian Beermann
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        https://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

/*
 * This limits the depth of the structures we can unpack, i.e. how many containers
 * are nestable.
 */
#define MSGPACK_EMBED_STACK_SIZE  (16)
#include "unpack_define.h"

// 2**32 - 1025
#define _MAX_VALUE ( (uint32_t) 4294966271UL )

#define MIN(x, y) ((x) < (y) ? (x): (y))

#ifdef DEBUG
#define SET_LAST_ERROR(msg) \
  fprintf(stderr, "cache_sync parse error: %s\n", (msg)); \
  u->last_error = (msg);
#else
#define SET_LAST_ERROR(msg) \
  u->last_error = (msg);
#endif

typedef struct unpack_user {
    /* Item.chunks and Item.part are at the top level; we don't care about anything else,
     * only need to track the current level to navigate arbitrary and unknown structure.
     * To discern keys from everything else on the top level we use expect_map_item_end.
     */
    int level;

    const char *last_error;

    HashIndex *chunks;

    /*
     * We don't care about most stuff. This flag tells us whether we're at the chunks structure,
     * meaning:
     * {'foo': 'bar', 'chunks': [...], 'stuff': ... }
     *                        ^-HERE-^
     */
    int inside_chunks;

    /* is this item a .part file (created for checkpointing inside files)? */
    int part;

    /* does this item have a chunks list in it? */
    int has_chunks;

    enum {
        /* the next thing is a map key at the Item root level,
         * and it might be the "chunks" or "part" key we're looking for */
        expect_map_key,

        /* blocking state to expect_map_key
         * {     'stuff': <complex and arbitrary structure>,     'chunks': [
         * emk     ->   emie    ->   ->       ->      ->   emk   ecb       eeboce
         *                (nested containers are tracked via level)
         * emk=expect_map_key, emie=expect_map_item_end, ecb=expect_chunks_begin,
         * eeboce=expect_entry_begin_or_chunks_end
         */
        expect_map_item_end,

        /* next thing must be the chunks array (array) */
        expect_chunks_begin,

        /* next thing must either be another CLE (array) or end of Item.chunks (array_end) */
        expect_entry_begin_or_chunks_end,

        /*
         * processing ChunkListEntry tuple:
         * expect_key, expect_size, expect_csize, expect_entry_end
         */
        /* next thing must be the key (raw, l=32) */
        expect_key,
        /* next thing must be the size (int) */
        expect_size,
        /* next thing must be the csize (int) */
        expect_csize,
        /* next thing must be the end of the CLE (array_end) */
        expect_entry_end,

        expect_item_begin
    } expect;

    /* collect values here for current chunklist entry */
    struct {
        char key[32];
        uint32_t csize;
        uint32_t size;
    } current;

    /* summing up chunks sizes here within a single item */
    struct {
        uint64_t size, csize;
    } item;

    /* total sizes and files count coming from all files */
    struct {
        uint64_t size, csize, num_files;
    } totals;

    /* total sizes and files count coming from part files */
    struct {
        uint64_t size, csize, num_files;
    } parts;

} unpack_user;

struct unpack_context;
typedef struct unpack_context unpack_context;
typedef int (*execute_fn)(unpack_context *ctx, const char* data, size_t len, size_t* off);

#define UNEXPECTED(what)                                            \
    if(u->inside_chunks || u->expect == expect_map_key) { \
        SET_LAST_ERROR("Unexpected object: " what);                 \
        return -1;                                                  \
    }

static inline void unpack_init_user_state(unpack_user *u)
{
    u->last_error = NULL;
    u->level = 0;
    u->inside_chunks = false;
    u->expect = expect_item_begin;
}

static inline int unpack_callback_uint64(unpack_user* u, int64_t d)
{
    switch(u->expect) {
        case expect_size:
            u->current.size = d;
            u->expect = expect_csize;
            break;
        case expect_csize:
            u->current.csize = d;
            u->expect = expect_entry_end;
            break;
        default:
            UNEXPECTED("integer");
    }
    return 0;
}

static inline int unpack_callback_uint32(unpack_user* u, uint32_t d)
{
    return unpack_callback_uint64(u, d);
}

static inline int unpack_callback_uint16(unpack_user* u, uint16_t d)
{
    return unpack_callback_uint64(u, d);
}

static inline int unpack_callback_uint8(unpack_user* u, uint8_t d)
{
    return unpack_callback_uint64(u, d);
}

static inline int unpack_callback_int64(unpack_user* u, uint64_t d)
{
    return unpack_callback_uint64(u, d);
}

static inline int unpack_callback_int32(unpack_user* u, int32_t d)
{
    return unpack_callback_uint64(u, d);
}

static inline int unpack_callback_int16(unpack_user* u, int16_t d)
{
    return unpack_callback_uint64(u, d);
}

static inline int unpack_callback_int8(unpack_user* u, int8_t d)
{
    return unpack_callback_uint64(u, d);
}

/* Ain't got anything to do with those floats */
static inline int unpack_callback_double(unpack_user* u, double d)
{
    (void)d;
    UNEXPECTED("double");
    return 0;
}

static inline int unpack_callback_float(unpack_user* u, float d)
{
    (void)d;
    UNEXPECTED("float");
    return 0;
}

/* nil/true/false — I/don't/care */
static inline int unpack_callback_nil(unpack_user* u)
{
    UNEXPECTED("nil");
    return 0;
}

static inline int unpack_callback_true(unpack_user* u)
{
    UNEXPECTED("true");
    return 0;
}

static inline int unpack_callback_false(unpack_user* u)
{
    UNEXPECTED("false");
    return 0;
}

static inline int unpack_callback_array(unpack_user* u, unsigned int n)
{
    switch(u->expect) {
    case expect_chunks_begin:
        /* b'chunks': [
         *            ^ */
        u->expect = expect_entry_begin_or_chunks_end;
        break;
    case expect_entry_begin_or_chunks_end:
        /* b'chunks': [ (
         *              ^ */
        if(n != 3) {
            SET_LAST_ERROR("Invalid chunk list entry length");
            return -1;
        }
        u->expect = expect_key;
        break;
    default:
        if(u->inside_chunks) {
            SET_LAST_ERROR("Unexpected array start");
            return -1;
        } else {
            u->level++;
            return 0;
        }
    }
    return 0;
}

static inline int unpack_callback_array_item(unpack_user* u, unsigned int current)
{
    (void)u; (void)current;
    return 0;
}

static inline int unpack_callback_array_end(unpack_user* u)
{
    uint32_t *cache_entry;
    uint32_t cache_values[3];
    uint64_t refcount;

    switch(u->expect) {
    case expect_entry_end:
        /* b'chunks': [ ( b'1234...', 123, 345 )
         *                                     ^ */
        cache_entry = (uint32_t*) hashindex_get(u->chunks, u->current.key);
        if(cache_entry) {
            refcount = _le32toh(cache_entry[0]);
            if(refcount > _MAX_VALUE) {
                SET_LAST_ERROR("invalid reference count");
                return -1;
            }
            refcount += 1;
            cache_entry[0] = _htole32(MIN(refcount, _MAX_VALUE));
        } else {
            /* refcount, size, csize */
            cache_values[0] = _htole32(1);
            cache_values[1] = _htole32(u->current.size);
            cache_values[2] = _htole32(u->current.csize);
            if(!hashindex_set(u->chunks, u->current.key, cache_values)) {
                SET_LAST_ERROR("hashindex_set failed");
                return -1;
            }
        }
        u->item.size += u->current.size;
        u->item.csize += u->current.csize;

        u->expect = expect_entry_begin_or_chunks_end;
        break;
    case expect_entry_begin_or_chunks_end:
        /* b'chunks': [ ]
         *              ^ */
        /* end of Item.chunks */
        u->inside_chunks = 0;
        u->expect = expect_map_item_end;
        break;
    default:
        if(u->inside_chunks) {
            SET_LAST_ERROR("Invalid state transition (unexpected array end)");
            return -1;
        } else {
            u->level--;
            return 0;
        }
    }
    return 0;
}

static inline int unpack_callback_map(unpack_user* u, unsigned int n)
{
    (void)n;

    if(u->level == 0) {
        if(u->expect != expect_item_begin) {
            SET_LAST_ERROR("Invalid state transition");  /* unreachable */
            return -1;
        }
        /* This begins a new Item */
        u->expect = expect_map_key;
        u->part = 0;
        u->has_chunks = 0;
        u->item.size = 0;
        u->item.csize = 0;
    }

    if(u->inside_chunks) {
        UNEXPECTED("map");
    }

    u->level++;

    return 0;
}

static inline int unpack_callback_map_item(unpack_user* u, unsigned int current)
{
    (void)u; (void)current;

    if(u->level == 1) {
        switch(u->expect) {
        case expect_map_item_end:
            u->expect = expect_map_key;
            break;
        default:
            SET_LAST_ERROR("Unexpected map item");
            return -1;
        }
    }
    return 0;
}

static inline int unpack_callback_map_end(unpack_user* u)
{
    u->level--;
    if(u->inside_chunks) {
        SET_LAST_ERROR("Unexpected map end");
        return -1;
    }
    if(u->level == 0) {
        /* This ends processing of an Item */
        if(u->has_chunks) {
            if(u->part) {
                u->parts.num_files += 1;
                u->parts.size += u->item.size;
                u->parts.csize += u->item.csize;
            }
            u->totals.num_files += 1;
            u->totals.size += u->item.size;
            u->totals.csize += u->item.csize;
        }
    }
    return 0;
}

static inline int unpack_callback_raw(unpack_user* u, const char* b, const char* p, unsigned int length)
{
    /* raw = what Borg uses for binary stuff and strings as well */
    /* Note: p points to an internal buffer which contains l bytes. */
    (void)b;

    switch(u->expect) {
    case expect_key:
        if(length != 32) {
            SET_LAST_ERROR("Incorrect key length");
            return -1;
        }
        memcpy(u->current.key, p, 32);
        u->expect = expect_size;
        break;
    case expect_map_key:
        if(length == 6 && !memcmp("chunks", p, 6)) {
            u->expect = expect_chunks_begin;
            u->inside_chunks = 1;
            u->has_chunks = 1;
        } else if(length == 4 && !memcmp("part", p, 4)) {
            u->expect = expect_map_item_end;
            u->part = 1;
        } else {
            u->expect = expect_map_item_end;
        }
        break;
    default:
        if(u->inside_chunks) {
            SET_LAST_ERROR("Unexpected bytes in chunks structure");
            return -1;
        }
    }
    return 0;
}

static inline int unpack_callback_bin(unpack_user* u, const char* b, const char* p, unsigned int length)
{
    (void)u; (void)b; (void)p; (void)length;
    UNEXPECTED("bin");
    return 0;
}

static inline int unpack_callback_ext(unpack_user* u, const char* base, const char* pos,
                                      unsigned int length)
{
    (void)u; (void)base; (void)pos; (void)length;
    UNEXPECTED("ext");
    return 0;
}

#include "unpack_template.h"
