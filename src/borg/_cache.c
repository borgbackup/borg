
#include <msgpack.h>

// 2**32 - 1025
#define _MAX_VALUE ( (uint32_t) 4294966271 )

#define MIN(x, y) ((x) < (y) ? (x): (y))

typedef struct {
    HashIndex *chunks;

    msgpack_unpacker unpacker;
    msgpack_unpacked unpacked;
    const char *error;
} CacheSyncCtx;

static CacheSyncCtx *
cache_sync_init(HashIndex *chunks)
{
    CacheSyncCtx *ctx;
    if (!(ctx = malloc(sizeof(CacheSyncCtx)))) {
        return NULL;
    }

    ctx->chunks = chunks;
    ctx->error = NULL;

    if(!msgpack_unpacker_init(&ctx->unpacker, MSGPACK_UNPACKER_INIT_BUFFER_SIZE)) {
        free(ctx);
        return NULL;
    }

    msgpack_unpacked_init(&ctx->unpacked);

    return ctx;
}

static void
cache_sync_free(CacheSyncCtx *ctx)
{
    msgpack_unpacker_destroy(&ctx->unpacker);
    msgpack_unpacked_destroy(&ctx->unpacked);
    free(ctx);
}

static const char *
cache_sync_error(CacheSyncCtx *ctx)
{
    return ctx->error;
}

static int
cache_process_chunks(CacheSyncCtx *ctx, msgpack_object_array *array)
{
    uint32_t i;
    const char *key;
    uint32_t cache_values[3];
    uint32_t *cache_entry;
    uint64_t refcount;
    msgpack_object *current;
    for (i = 0; i < array->size; i++) {
        current = &array->ptr[i];

        if (current->type != MSGPACK_OBJECT_ARRAY || current->via.array.size != 3
            || current->via.array.ptr[0].type != MSGPACK_OBJECT_STR || current->via.array.ptr[0].via.str.size != 32
            || current->via.array.ptr[1].type != MSGPACK_OBJECT_POSITIVE_INTEGER
            || current->via.array.ptr[2].type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
            ctx->error = "Malformed chunk list entry";
            return 0;
        }

        key = current->via.array.ptr[0].via.str.ptr;
        cache_entry = (uint32_t*) hashindex_get(ctx->chunks, key);
        if (cache_entry) {
            refcount = _le32toh(cache_entry[0]);
            refcount += 1;
            cache_entry[0] = _htole32(MIN(refcount, _MAX_VALUE));
        } else {
            /* refcount, size, csize */
            cache_values[0] = 1;
            cache_values[1] = current->via.array.ptr[1].via.u64;
            cache_values[2] = current->via.array.ptr[2].via.u64;
            if (!hashindex_set(ctx->chunks, key, cache_values)) {
                ctx->error = "hashindex_set failed";
                return 0;
            }
        }
    }
    return 1;
}

/**
 * feed data to the cache synchronizer
 * 0 = abort, 1 = continue
 * abort is a regular condition, check cache_sync_error
 */
static int
cache_sync_feed(CacheSyncCtx *ctx, void *data, uint32_t length)
{
    msgpack_unpack_return unpack_status;

    /* grow buffer if necessary */
    if (msgpack_unpacker_buffer_capacity(&ctx->unpacker) < length) {
        if (!msgpack_unpacker_reserve_buffer(&ctx->unpacker, length)) {
            return 0;
        }
    }

    memcpy(msgpack_unpacker_buffer(&ctx->unpacker), data, length);
    msgpack_unpacker_buffer_consumed(&ctx->unpacker, length);

    do {
        unpack_status = msgpack_unpacker_next(&ctx->unpacker, &ctx->unpacked);

        switch (unpack_status) {
        case MSGPACK_UNPACK_SUCCESS:
            {
                uint32_t i;
                msgpack_object *item = &ctx->unpacked.data;
                msgpack_object_kv *current;

                if (item->type != MSGPACK_OBJECT_MAP) {
                    ctx->error = "Unexpected data type in item stream";
                    return 0;
                }

                for (i = 0; i < item->via.map.size; i++) {
                    current = &item->via.map.ptr[i];

                    if (current->key.type != MSGPACK_OBJECT_STR) {
                        ctx->error = "Invalid key data type in item";
                        return 0;
                    }

                    if (current->key.via.str.size == 6
                        && !memcmp(current->key.via.str.ptr, "chunks", 6)) {

                        if (current->val.type != MSGPACK_OBJECT_ARRAY) {
                            ctx->error = "Unexpected value type of item chunks";
                            return 0;
                        }

                        if (!cache_process_chunks(ctx, &current->val.via.array)) {
                            return 0;
                        }
                    }
                }
            }
            break;
        case MSGPACK_UNPACK_PARSE_ERROR:
            ctx->error = "Malformed msgpack";
            return 0;
        default:
            break;
        }
    } while (unpack_status != MSGPACK_UNPACK_CONTINUE);

    return 1;
}
