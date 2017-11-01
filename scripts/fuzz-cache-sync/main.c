
#define BORG_NO_PYTHON

#include "../../src/borg/_hashindex.c"
#include "../../src/borg/cache_sync/cache_sync.c"

#define BUFSZ 32768

int main() {
    char buf[BUFSZ];
    int len, ret;
    CacheSyncCtx *ctx;
    HashIndex *idx;

    /* capacity, key size, value size */
    idx = hashindex_init(0, 32, 12);
    ctx = cache_sync_init(idx);

    while (1) {
        len = read(0, buf, BUFSZ);
        if (!len) {
            break;
        }
        ret = cache_sync_feed(ctx, buf, len);
        if(!ret && cache_sync_error(ctx)) {
            fprintf(stderr, "error: %s\n", cache_sync_error(ctx));
            return 1;
        }
    }
    hashindex_free(idx);
    cache_sync_free(ctx);
    return 0;
}
