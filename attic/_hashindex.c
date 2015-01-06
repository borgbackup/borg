#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#if defined(BYTE_ORDER)&&(BYTE_ORDER == BIG_ENDIAN)
#define _le32toh(x) __builtin_bswap32(x)
#define _htole32(x) __builtin_bswap32(x)
#elif defined(BYTE_ORDER)&&(BYTE_ORDER == LITTLE_ENDIAN)
#define _le32toh(x) (x)
#define _htole32(x) (x)
#else
#error Unknown byte order
#endif

typedef struct {
    char magic[8];
    int32_t num_entries;
    int32_t num_buckets;
    int8_t  key_size;
    int8_t  value_size;
} __attribute__((__packed__)) HashHeader;

typedef struct {
    void *data;
    void *buckets;
    int num_entries;
    int num_buckets;
    int key_size;
    int value_size;
    off_t bucket_size;
    int lower_limit;
    int upper_limit;
    off_t data_len;
} HashIndex;

#define MAGIC "ATTICIDX"
#define EMPTY _htole32(0xffffffff)
#define DELETED _htole32(0xfffffffe)
#define MAX_BUCKET_SIZE 512
#define BUCKET_LOWER_LIMIT .25
#define BUCKET_UPPER_LIMIT .90
#define MIN_BUCKETS 1024
#define MAX(x, y) ((x) > (y) ? (x): (y))
#define BUCKET_ADDR(index, idx) (index->buckets + (idx * index->bucket_size))

#define BUCKET_IS_DELETED(index, idx) (*((uint32_t *)(BUCKET_ADDR(index, idx) + index->key_size)) == DELETED)
#define BUCKET_IS_EMPTY(index, idx) (*((uint32_t *)(BUCKET_ADDR(index, idx) + index->key_size)) == EMPTY)

#define BUCKET_MATCHES_KEY(index, idx, key) (memcmp(key, BUCKET_ADDR(index, idx), index->key_size) == 0)

#define BUCKET_MARK_DELETED(index, idx) (*((uint32_t *)(BUCKET_ADDR(index, idx) + index->key_size)) = DELETED)
#define BUCKET_MARK_EMPTY(index, idx) (*((uint32_t *)(BUCKET_ADDR(index, idx) + index->key_size)) = EMPTY)

#define EPRINTF(msg, ...) fprintf(stderr, "hashindex: " msg "\n", ##__VA_ARGS__)
#define EPRINTF_PATH(path, msg, ...) fprintf(stderr, "hashindex: %s: " msg "\n", path, ##__VA_ARGS__)

static HashIndex *hashindex_read(const char *path);
static int hashindex_write(HashIndex *index, const char *path);
static HashIndex *hashindex_init(int capacity, int key_size, int value_size);
static const void *hashindex_get(HashIndex *index, const void *key);
static int hashindex_set(HashIndex *index, const void *key, const void *value);
static int hashindex_delete(HashIndex *index, const void *key);
static void *hashindex_next_key(HashIndex *index, const void *key);

/* Private API */
static int
hashindex_index(HashIndex *index, const void *key)
{
    return _le32toh(*((uint32_t *)key)) % index->num_buckets;
}

static int
hashindex_lookup(HashIndex *index, const void *key)
{
    int didx = -1;
    int start = hashindex_index(index, key);
    int idx = start;
    for(;;) {
        if(BUCKET_IS_EMPTY(index, idx))
        {
            return -1;
        }
        if(BUCKET_IS_DELETED(index, idx)) {
            if(didx == -1) {
                didx = idx;
            }
        }
        else if(BUCKET_MATCHES_KEY(index, idx, key)) {
            if (didx != -1) {
                memcpy(BUCKET_ADDR(index, didx), BUCKET_ADDR(index, idx), index->bucket_size);
                BUCKET_MARK_DELETED(index, idx);
                idx = didx;
            }
            return idx;
        }
        idx = (idx + 1) % index->num_buckets;
        if(idx == start) {
            return -1;
        }
    }
}

static int
hashindex_resize(HashIndex *index, int capacity)
{
    HashIndex *new;
    void *key = NULL;

    if(!(new = hashindex_init(capacity, index->key_size, index->value_size))) {
        return 0;
    }
    while((key = hashindex_next_key(index, key))) {
        hashindex_set(new, key, hashindex_get(index, key));
    }
    free(index->data);
    index->data = new->data;
    index->data_len = new->data_len;
    index->num_buckets = new->num_buckets;
    index->lower_limit = new->lower_limit;
    index->upper_limit = new->upper_limit;
    index->buckets = new->buckets;
    free(new);
    return 1;
}

/* Public API */
static HashIndex *
hashindex_read(const char *path)
{
    FILE *fd;
    off_t length;
    HashHeader header;
    HashIndex *index = NULL;

    if((fd = fopen(path, "r")) == NULL) {
        EPRINTF_PATH(path, "fopen failed");
        return NULL;
    }
    if(fread(&header, 1, sizeof(HashHeader), fd) != sizeof(HashHeader)) {
        EPRINTF_PATH(path, "fread failed");
        goto fail;
    }
    if(fseek(fd, 0, SEEK_END) < 0) {
        EPRINTF_PATH(path, "fseek failed");
        goto fail;
    }
    if((length = ftell(fd)) < 0) {
        EPRINTF_PATH(path, "ftell failed");
        goto fail;
    }
    if(fseek(fd, 0, SEEK_SET) < 0) {
        EPRINTF_PATH(path, "fseek failed");
        goto fail;
    }
    if(memcmp(header.magic, MAGIC, 8)) {
        EPRINTF_PATH(path, "Unknown file header");
        goto fail;
    }
    if(length != sizeof(HashHeader) + (off_t)_le32toh(header.num_buckets) * (header.key_size + header.value_size)) {
        EPRINTF_PATH(path, "Incorrect file length");
        goto fail;
    }
    if(!(index = malloc(sizeof(HashIndex)))) {
        EPRINTF_PATH(path, "malloc failed");
        goto fail;
    }
    if(!(index->data = malloc(length))) {
        EPRINTF_PATH(path, "malloc failed");
        free(index);
        index = NULL;
        goto fail;
    }
    if(fread(index->data, 1, length, fd) != length) {
        EPRINTF_PATH(path, "fread failed");
        free(index->data);
        free(index);
        index = NULL;
        goto fail;
    }
    index->data_len = length;
    index->num_entries = _le32toh(header.num_entries);
    index->num_buckets = _le32toh(header.num_buckets);
    index->key_size = header.key_size;
    index->value_size = header.value_size;
    index->bucket_size = index->key_size + index->value_size;
    index->buckets = index->data + sizeof(HashHeader);
    index->lower_limit = index->num_buckets > MIN_BUCKETS ? ((int)(index->num_buckets * BUCKET_LOWER_LIMIT)) : 0;
    index->upper_limit = (int)(index->num_buckets * BUCKET_UPPER_LIMIT);
fail:
    if(fclose(fd) < 0) {
        EPRINTF_PATH(path, "fclose failed");
    }
    return index;
}

static HashIndex *
hashindex_init(int capacity, int key_size, int value_size)
{
    HashIndex *index;
    HashHeader header = {
        .magic = MAGIC, .num_entries = 0, .key_size = key_size, .value_size = value_size
    };
    int i;
    capacity = MAX(MIN_BUCKETS, capacity);

    if(!(index = malloc(sizeof(HashIndex)))) {
        EPRINTF("malloc failed");
        return NULL;
    }
    index->data_len = sizeof(HashHeader) + (off_t)capacity * (key_size + value_size);
    if(!(index->data = calloc(index->data_len, 1))) {
        EPRINTF("malloc failed");
        free(index);
        return NULL;
    }
    index->num_entries = 0;
    index->key_size = key_size;
    index->value_size = value_size;
    index->num_buckets = capacity;
    index->bucket_size = index->key_size + index->value_size;
    index->lower_limit = index->num_buckets > MIN_BUCKETS ? ((int)(index->num_buckets * BUCKET_LOWER_LIMIT)) : 0;
    index->upper_limit = (int)(index->num_buckets * BUCKET_UPPER_LIMIT);
    index->buckets = index->data + sizeof(HashHeader);
    memcpy(index->data, &header, sizeof(HashHeader));
    for(i = 0; i < capacity; i++) {
        BUCKET_MARK_EMPTY(index, i);
    }
    return index;
}

static void
hashindex_free(HashIndex *index)
{
    free(index->data);
    free(index);
}

static int
hashindex_write(HashIndex *index, const char *path)
{
    FILE *fd;
    int ret = 1;

    if((fd = fopen(path, "w")) == NULL) {
        EPRINTF_PATH(path, "open failed");
        fprintf(stderr, "Failed to open %s for writing\n", path);
        return 0;
    }
    *((uint32_t *)(index->data + 8)) = _htole32(index->num_entries);
    *((uint32_t *)(index->data + 12)) = _htole32(index->num_buckets);
    if(fwrite(index->data, 1, index->data_len, fd) != index->data_len) {
        EPRINTF_PATH(path, "fwrite failed");
        ret = 0;
    }
    if(fclose(fd) < 0) {
        EPRINTF_PATH(path, "fclose failed");
    }
    return ret;
}

static const void *
hashindex_get(HashIndex *index, const void *key)
{
    int idx = hashindex_lookup(index, key);
    if(idx < 0) {
        return NULL;
    }
    return BUCKET_ADDR(index, idx) + index->key_size;
}

static int
hashindex_set(HashIndex *index, const void *key, const void *value)
{
    int idx = hashindex_lookup(index, key);
    uint8_t *ptr;
    if(idx < 0)
    {
        if(index->num_entries > index->upper_limit) {
            if(!hashindex_resize(index, index->num_buckets * 2)) {
                return 0;
            }
        }
        idx = hashindex_index(index, key);
        while(!BUCKET_IS_EMPTY(index, idx) && !BUCKET_IS_DELETED(index, idx)) {
            idx = (idx + 1) % index->num_buckets;
        }
        ptr = BUCKET_ADDR(index, idx);
        memcpy(ptr, key, index->key_size);
        memcpy(ptr + index->key_size, value, index->value_size);
        index->num_entries += 1;
    }
    else
    {
        memcpy(BUCKET_ADDR(index, idx) + index->key_size, value, index->value_size);
    }
    return 1;
}

static int
hashindex_delete(HashIndex *index, const void *key)
{
    int idx = hashindex_lookup(index, key);
    if (idx < 0) {
        return 1;
    }
    BUCKET_MARK_DELETED(index, idx);
    index->num_entries -= 1;
    if(index->num_entries < index->lower_limit) {
        if(!hashindex_resize(index, index->num_buckets / 2)) {
            return 0;
        }
    }
    return 1;
}

static void *
hashindex_next_key(HashIndex *index, const void *key)
{
    int idx = 0;
    if(key) {
        idx = 1 + (key - index->buckets) / index->bucket_size;
    }
    if (idx == index->num_buckets) {
        return NULL;
    }
    while(BUCKET_IS_EMPTY(index, idx) || BUCKET_IS_DELETED(index, idx)) {
        idx ++;
        if (idx == index->num_buckets) {
            return NULL;
        }
    }
    return BUCKET_ADDR(index, idx);
}

static int
hashindex_get_size(HashIndex *index)
{
    return index->num_entries;
}

static void
hashindex_summarize(HashIndex *index, long long *total_size, long long *total_csize, long long *total_unique_size, long long *total_unique_csize)
{
    int64_t size = 0, csize = 0, unique_size = 0, unique_csize = 0;
    const int32_t *values;
    void *key = NULL;

    while((key = hashindex_next_key(index, key))) {
        values = key + 32;
        unique_size += values[1];
        unique_csize += values[2];
        size += values[0] * values[1];
        csize += values[0] * values[2];
    }
    *total_size = size;
    *total_csize = csize;
    *total_unique_size = unique_size;
    *total_unique_csize = unique_csize;
}

