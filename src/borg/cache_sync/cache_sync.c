/*
 * Borg cache synchronizer,
 * high level interface.
 *
 * These routines parse msgpacked item metadata and update a HashIndex
 * with all chunks that are referenced from the items.
 *
 * This file only contains some initialization and buffer management.
 *
 * The parser is split in two parts, somewhat similar to lexer/parser combinations:
 *
 * unpack_template.h munches msgpack and calls a specific callback for each object
 * encountered (e.g. beginning of a map, an integer, a string, a map item etc.).
 *
 * unpack.h implements these callbacks and uses another state machine to
 * extract chunk references from it.
 */

#include "unpack.h"

typedef struct {
    unpack_context ctx;

    char *buf;
    size_t head;
    size_t tail;
    size_t size;
} CacheSyncCtx;

static CacheSyncCtx *
cache_sync_init(HashIndex *chunks)
{
    CacheSyncCtx *ctx;
    if (!(ctx = (CacheSyncCtx*)malloc(sizeof(CacheSyncCtx)))) {
        return NULL;
    }

    unpack_init(&ctx->ctx);
    /* needs to be set only once */
    ctx->ctx.user.chunks = chunks;
    ctx->ctx.user.parts.size = 0;
    ctx->ctx.user.parts.csize = 0;
    ctx->ctx.user.parts.num_files = 0;
    ctx->ctx.user.totals.size = 0;
    ctx->ctx.user.totals.csize = 0;
    ctx->ctx.user.totals.num_files = 0;
    ctx->buf = NULL;
    ctx->head = 0;
    ctx->tail = 0;
    ctx->size = 0;

    return ctx;
}

static void
cache_sync_free(CacheSyncCtx *ctx)
{
    if(ctx->buf) {
        free(ctx->buf);
    }
    free(ctx);
}

static const char *
cache_sync_error(const CacheSyncCtx *ctx)
{
    return ctx->ctx.user.last_error;
}

static uint64_t
cache_sync_num_files_totals(const CacheSyncCtx *ctx)
{
    return ctx->ctx.user.totals.num_files;
}

static uint64_t
cache_sync_num_files_parts(const CacheSyncCtx *ctx)
{
    return ctx->ctx.user.parts.num_files;
}

static uint64_t
cache_sync_size_totals(const CacheSyncCtx *ctx)
{
    return ctx->ctx.user.totals.size;
}

static uint64_t
cache_sync_size_parts(const CacheSyncCtx *ctx)
{
    return ctx->ctx.user.parts.size;
}

static uint64_t
cache_sync_csize_totals(const CacheSyncCtx *ctx)
{
    return ctx->ctx.user.totals.csize;
}

static uint64_t
cache_sync_csize_parts(const CacheSyncCtx *ctx)
{
    return ctx->ctx.user.parts.csize;
}

/**
 * feed data to the cache synchronizer
 * 0 = abort, 1 = continue
 * abort is a regular condition, check cache_sync_error
 */
static int
cache_sync_feed(CacheSyncCtx *ctx, void *data, uint32_t length)
{
    size_t new_size;
    int ret;
    char *new_buf;

    if(ctx->tail + length > ctx->size) {
        if((ctx->tail - ctx->head) + length <= ctx->size) {
            /* |  XXXXX| -> move data in buffer backwards -> |XXXXX  | */
            memmove(ctx->buf, ctx->buf + ctx->head, ctx->tail - ctx->head);
            ctx->tail -= ctx->head;
            ctx->head = 0;
        } else {
            /* must expand buffer to fit all data */
            new_size = (ctx->tail - ctx->head) + length;
            new_buf = (char*) malloc(new_size);
            if(!new_buf) {
                ctx->ctx.user.last_error = "cache_sync_feed: unable to allocate buffer";
                return 0;
            }
            if(ctx->buf) {
                memcpy(new_buf, ctx->buf + ctx->head, ctx->tail - ctx->head);
                free(ctx->buf);
            }
            ctx->buf = new_buf;
            ctx->tail -= ctx->head;
            ctx->head = 0;
            ctx->size = new_size;
        }
    }

    memcpy(ctx->buf + ctx->tail, data, length);
    ctx->tail += length;

    while(1) {
        if(ctx->head >= ctx->tail) {
            return 1;  /* request more bytes */
        }

        ret = unpack_execute(&ctx->ctx, ctx->buf, ctx->tail, &ctx->head);
        if(ret == 1) {
            unpack_init(&ctx->ctx);
            continue;
        } else if(ret == 0) {
            return 1;
        } else {
            if(!ctx->ctx.user.last_error) {
                ctx->ctx.user.last_error = "Unknown error";
            }
            return 0;
        }
    }
    /* unreachable */
    return 1;
}
